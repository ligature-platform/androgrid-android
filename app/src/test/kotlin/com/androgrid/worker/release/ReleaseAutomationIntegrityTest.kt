package com.androgrid.worker.release

import android.graphics.BitmapFactory
import com.androgrid.worker.enrollment.QrCodeDecoder
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * Validates the release automation pipeline configuration, R8/ProGuard preservation rules,
 * Gradle signing keystore configuration, and typographic integrity for Android release packaging.
 *
 * Traces to: AG-SPEC-2026-V2, [REQ-VER-001], [REQ-VER-002], [NFR-PERF-001]
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ReleaseAutomationIntegrityTest {

    private fun getProjectRootDir(): File {
        var dir = File(".").canonicalFile
        while (dir.parentFile != null && !File(dir, "settings.gradle.kts").exists()) {
            dir = dir.parentFile
        }
        return dir
    }

    /**
     * Validates that .github/workflows/release.yml exists and triggers on version tags (v*),
     * executing release APK and AAB assembly, SHA-256 digest generation, and GitHub release upload.
     *
     * Traces to: [REQ-VER-001], [NFR-PERF-001]
     */
    @Test
    fun testReleaseWorkflowConfigurationIntegrity() {
        val rootDir = getProjectRootDir()
        val workflowFile = File(rootDir, ".github/workflows/release.yml")
        assertThat(workflowFile.exists()).isTrue()

        val content = workflowFile.readText(Charsets.UTF_8)
        assertThat(content).isNotEmpty()

        // Verify version tag trigger
        assertThat(content).contains("tags:")
        assertThat(content).contains("v*")

        // Verify Gradle assembly tasks
        assertThat(content).contains("assembleRelease")
        assertThat(content).contains("bundleRelease")

        // Verify Keystore decoding from GitHub Secrets
        assertThat(content).contains("RELEASE_KEYSTORE_BASE64")

        // Verify SHA-256 checksum consolidation
        assertThat(content).contains("SHA256SUMS.txt")

        // Verify permanent release APK asset naming per Issue #67
        assertThat(content).contains("androgrid-worker.apk")
        assertThat(content).contains("download-qr.png")

        // Verify fail-closed apksigner verification and environment-based keytool password
        assertThat(content).contains("storepass:env RELEASE_KEYSTORE_PASSWORD")
        assertThat(content).contains("apksigner")
        assertThat(content).doesNotContain("|| true")

        // Verify 25 MB APK size boundary check
        assertThat(content).contains("25 * 1024 * 1024")

        // Verify release upload / publication
        assertThat(content).contains("gh release")
    }

    /**
     * Validates that mobile download QR code assets exist, decode programmatically to the
     * canonical release URL via ZXing, and are properly referenced in README.md.
     *
     * Traces to: [REQ-OP-001], Issue #67
     */
    @Test
    fun testDownloadQrAssetsAndReadmeIntegration() {
        val rootDir = getProjectRootDir()
        val assetsDir = File(rootDir, "docs/assets")
        val qrPng = File(assetsDir, "download-qr.png")
        val qrSvg = File(assetsDir, "download-qr.svg")

        assertThat(qrPng.exists()).isTrue()
        assertThat(qrPng.length()).isGreaterThan(500L)

        // Programmatically decode QR PNG content via QrCodeDecoder to guarantee URL integrity
        val bitmap = BitmapFactory.decodeFile(qrPng.absolutePath)
        assertThat(bitmap).isNotNull()
        val decodedUrl = QrCodeDecoder.decodeBitmap(bitmap)

        assertThat(decodedUrl).isEqualTo(
            "https://github.com/ligature-platform/androgrid-android/releases/latest/download/androgrid-worker.apk"
        )

        assertThat(qrSvg.exists()).isTrue()
        assertThat(qrSvg.length()).isGreaterThan(500L)
        val svgContent = qrSvg.readText(Charsets.UTF_8)
        assertThat(svgContent).contains("<svg")
        assertThat(svgContent).contains("</svg>")

        val readmeFile = File(rootDir, "README.md")
        assertThat(readmeFile.exists()).isTrue()
        val readmeContent = readmeFile.readText(Charsets.UTF_8)

        assertThat(readmeContent).contains("docs/assets/download-qr.png")
        assertThat(readmeContent).contains("androgrid-worker.apk")
        assertThat(readmeContent).contains("releases/latest/download/androgrid-worker.apk")
    }

    /**
     * Validates that app/build.gradle.kts bounds release native ABI to arm64-v8a for alpha distribution
     * keeping release APK size under 25 MB while preserving debug builds for developer emulators.
     *
     * Traces to: [REQ-VER-001], Issue #67
     */
    @Test
    fun testHardwareScopeArm64AbiFilterBound() {
        val rootDir = getProjectRootDir()
        val buildGradleFile = File(rootDir, "app/build.gradle.kts")
        assertThat(buildGradleFile.exists()).isTrue()

        val content = buildGradleFile.readText(Charsets.UTF_8)
        assertThat(content).contains("abiFilters")
        assertThat(content).contains("arm64-v8a")
    }

    /**
     * Validates that app/build.gradle.kts defines release signing configuration with
     * fallback to debug signing when release keystore credentials are not present.
     *
     * Traces to: [REQ-VER-001]
     */
    @Test
    fun testGradleReleaseSigningConfigurationWithDebugFallback() {
        val rootDir = getProjectRootDir()
        val buildGradleFile = File(rootDir, "app/build.gradle.kts")
        assertThat(buildGradleFile.exists()).isTrue()

        val content = buildGradleFile.readText(Charsets.UTF_8)

        // Verify signingConfigs block definition
        assertThat(content).contains("signingConfigs")

        // Verify release signing block
        assertThat(content).contains("create(\"release\")")

        // Verify fallback mechanism to debug signing
        assertThat(content).contains("debug")

        // Verify release build type references signing configuration
        assertThat(content).contains("signingConfig")

        // Verify ProGuard rules configuration is enabled for release
        assertThat(content).contains("proguard-rules.pro")
    }

    /**
     * Validates that app/proguard-rules.pro exists and explicitly preserves required
     * reflection-free Protobuf Lite models, gRPC OkHttp transport, Chicory WASM runtime,
     * and Jetpack WorkManager worker classes.
     *
     * Traces to: [REQ-VER-002], [REQ-OP-001]
     */
    @Test
    fun testProguardRulesPreserveCriticalDependencies() {
        val rootDir = getProjectRootDir()
        val proguardFile = File(rootDir, "app/proguard-rules.pro")
        assertThat(proguardFile.exists()).isTrue()

        val rawContent = proguardFile.readText(Charsets.UTF_8)
        assertThat(rawContent).isNotEmpty()

        // Verify comments do not make false claims regarding reflection-free status
        assertThat(rawContent).doesNotContain("reflection-free")

        // Strip comments and empty lines to assert active executable directives
        val activeLines = proguardFile.readLines(Charsets.UTF_8)
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
        val activeDirectives = activeLines.joinToString("\n")

        // Verify Protobuf Lite runtime preservation
        assertThat(activeDirectives).contains("com.google.protobuf")

        // Verify obsolete and phantom namespaces are eliminated
        assertThat(activeDirectives).doesNotContain("com.androgrid.contract")

        // Verify first-party contract warnings are never suppressed
        assertThat(activeDirectives).doesNotContain("-dontwarn com.androgrid.v1")

        // Verify type-hierarchical field preservation on instantiated GeneratedMessageLite subclasses
        assertThat(activeDirectives).contains("-keepclassmembers class * extends com.google.protobuf.GeneratedMessageLite")
        assertThat(activeDirectives).contains("<fields>;")
        assertThat(activeDirectives).contains("-keepclassmembers class * extends com.google.protobuf.GeneratedMessageLite\$Builder")
        assertThat(activeDirectives).doesNotContain("-keep class * extends com.google.protobuf.GeneratedMessageLite\$Builder")

        // Verify mobile worker client gRPC service stubs are preserved
        assertThat(activeDirectives).contains("com.androgrid.v1.AndroGridServiceGrpc")
        assertThat(activeDirectives).contains("com.androgrid.v1.EnrollmentServiceGrpc")

        // Verify gRPC transport preservation
        assertThat(activeDirectives).contains("io.grpc")

        // Verify Chicory WASM runtime preservation
        assertThat(activeDirectives).contains("com.dylibso.chicory")

        // Verify Jetpack WorkManager and Worker preservation
        assertThat(activeDirectives).contains("androidx.work")
        assertThat(activeDirectives).contains("com.androgrid.worker.service")
    }

    /**
     * Asserts zero occurrences of forbidden Unicode em dashes (U+2014) and en dashes (U+2013)
     * in the release workflow and ProGuard configuration files.
     *
     * Traces to: AGENTS.md Typographic Standards
     */
    @Test
    fun testZeroUnicodeDashesInReleaseArtifacts() {
        val rootDir = getProjectRootDir()
        val targetFiles = listOf(
            File(rootDir, ".github/workflows/release.yml"),
            File(rootDir, "app/proguard-rules.pro"),
            File(rootDir, "app/build.gradle.kts")
        )

        for (file in targetFiles) {
            if (file.exists()) {
                val content = file.readText(Charsets.UTF_8)
                assertThat(content).doesNotContain("\u2014")
                assertThat(content).doesNotContain("\u2013")
            }
        }
    }
}
