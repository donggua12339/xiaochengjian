package com.xcj.defender

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log

/**
 * 模拟器检测器(Java 层)
 *
 * 详见 ADR 0088 §EmulatorDetector
 *
 * 检测方式:
 *  - Build 属性(FINGERPRINT/MODEL/MANUFACTURER/BRAND/DEVICE/PRODUCT/HARDWARE)
 *  - 传感器(模拟器通常无传感器)
 *  - 电话号码(模拟器通常无电话功能)
 *  - 硬件特征(QEMU/goldfish/ranchu)
 *
 * 响应:warn(Toast + 上报),不 kill
 */
class EmulatorDetector(private val context: Context) {

    companion object {
        private const val TAG = "DefenderEmulator"

        private val EMULATOR_KEYWORDS = listOf(
            "generic", "sdk", "google_sdk", "emulator", "virtual",
            "goldfish", "ranchu", "vbox", "nox", "bluestacks", "mumu",
            "x86", "genymotion", "andy"
        )
    }

    /**
     * 组合检测
     *
     * @return true=检测到模拟器 / false=未检测到
     */
    fun detect(): Boolean {
        // Build 属性
        if (checkBuildProperties()) return true

        // 传感器
        if (checkSensors()) return true

        // 电话号码
        if (checkPhoneType()) return true

        // 硬件特征
        if (checkHardware()) return true

        Log.i(TAG, "模拟器检测通过(未检测到模拟器)")
        return false
    }

    /**
     * A:Build 属性检测
     */
    private fun checkBuildProperties(): Boolean {
        val buildProps = listOf(
            Build.FINGERPRINT,
            Build.MODEL,
            Build.MANUFACTURER,
            Build.BRAND,
            Build.DEVICE,
            Build.PRODUCT,
            Build.HARDWARE,
        )

        for (prop in buildProps) {
            if (prop == null) continue
            for (keyword in EMULATOR_KEYWORDS) {
                if (prop.contains(keyword, ignoreCase = true)) {
                    Log.e(TAG, "Build 属性检测到模拟器: $prop (含 $keyword)")
                    return true
                }
            }
        }

        // 检查 Build.BOARD(模拟器常为 goldfish/ranchu)
        val board = Build.BOARD ?: ""
        if (board.contains("goldfish", ignoreCase = true) ||
            board.contains("ranchu", ignoreCase = true)) {
            Log.e(TAG, "Build.BOARD 检测到模拟器: $board")
            return true
        }

        return false
    }

    /**
     * B:传感器检测(模拟器通常无传感器或传感器数量极少)
     */
    private fun checkSensors(): Boolean {
        return try {
            val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
            val sensors = sensorManager.getSensorList(Sensor.TYPE_ALL)

            // 模拟器通常传感器数量 < 5
            if (sensors.isEmpty()) {
                Log.e(TAG, "无传感器(模拟器特征)")
                return true
            }

            // 检查关键传感器(加速度计 + 陀螺仪)
            val hasAccelerometer = sensors.any { it.type == Sensor.TYPE_ACCELEROMETER }
            val hasGyroscope = sensors.any { it.type == Sensor.TYPE_GYROSCOPE }

            if (!hasAccelerometer && !hasGyroscope) {
                Log.e(TAG, "无加速度计和陀螺仪(模拟器特征)")
                return true
            }

            false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * C:电话号码检测(模拟器通常无电话功能)
     */
    private fun checkPhoneType(): Boolean {
        return try {
            val telephony = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
            val phoneType = telephony.phoneType

            if (phoneType == TelephonyManager.PHONE_TYPE_NONE) {
                Log.e(TAG, "无电话功能(PHONE_TYPE_NONE,模拟器特征)")
                return true
            }

            false
        } catch (e: Exception) {
            // TelephonyManager 权限不足,不算模拟器
            false
        }
    }

    /**
     * D:硬件特征检测(QEMU/goldfish/ranchu)
     */
    private fun checkHardware(): Boolean {
        val hardware = Build.HARDWARE ?: ""
        val bootloader = Build.BOOTLOADER ?: ""

        if (hardware.contains("goldfish", ignoreCase = true) ||
            hardware.contains("ranchu", ignoreCase = true) ||
            hardware.contains("vbox", ignoreCase = true)) {
            Log.e(TAG, "硬件特征检测到模拟器: hardware=$hardware")
            return true
        }

        if (bootloader.contains("goldfish", ignoreCase = true) ||
            bootloader.contains("ranchu", ignoreCase = true)) {
            Log.e(TAG, "bootloader 检测到模拟器: $bootloader")
            return true
        }

        // 检查 /proc/cpuinfo 含 goldfish
        try {
            val cpuinfo = java.io.File("/proc/cpuinfo").readText()
            if (cpuinfo.contains("goldfish", ignoreCase = true) ||
                cpuinfo.contains("ranchu", ignoreCase = true)) {
                Log.e(TAG, "cpuinfo 检测到模拟器特征")
                return true
            }
        } catch (e: Exception) {
            // 读取失败不算模拟器
        }

        return false
    }
}
