#!/bin/bash
ADB="${ANDROID_SDK_ROOT:-$HOME/android-sdk}/platform-tools/platform-tools/adb"

DEVICE="${1:-samsung}"

case "$DEVICE" in
  samsung)
    MODEL="SM-S911B"; BRAND="samsung"; DEVICE_NAME="dm1q"; BOARD="kalama"
    FP="samsung/dm1qxx/dm1q:14/UP1A.231005.007/S911BXXU2AWK1:user/release-keys"
    ;;
  pixel)
    MODEL="Pixel 8 Pro"; BRAND="google"; DEVICE_NAME="husky"; BOARD="shiba"
    FP="google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys"
    ;;
  xiaomi)
    MODEL="2201116SG"; BRAND="Xiaomi"; DEVICE_NAME="vili"; BOARD="taro"
    FP="Xiaomi/vili/vili:14/UKQ1.230804.001/V816.0.3.0.UKDMIXM:user/release-keys"
    ;;
  oppo)
    MODEL="CPH2449"; BRAND="OPPO"; DEVICE_NAME="OP5958L1"; BOARD="taro"
    FP="OPPO/CPH2449/OP5958L1:14/UP1A.231005.007/T.R4T3.1576a45-1:user/release-keys"
    ;;
  *)
    echo "Usage: $0 [samsung|pixel|xiaomi|oppo]"; exit 1
    ;;
esac

echo "[*] Spoofing as $BRAND $MODEL..."

$ADB root && sleep 2 && $ADB remount

for PROP_FILE in /system/build.prop /vendor/build.prop /product/build.prop; do
  $ADB shell "cat >> $PROP_FILE << EOF
ro.product.manufacturer=$BRAND
ro.product.brand=$BRAND
ro.product.model=$MODEL
ro.product.device=$DEVICE_NAME
ro.product.board=$BOARD
ro.board.platform=$BOARD
ro.build.fingerprint=$FP
ro.build.tags=release-keys
ro.build.type=user
EOF"
done

echo "[+] Device spoofed as $BRAND $MODEL"
echo "[*] Reboot required: $ADB reboot"
