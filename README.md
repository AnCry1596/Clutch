# Clutch

*Clutch* is a high-speed iOS decryption tool. Clutch supports the iPhone, iPod Touch, and iPad as well as all iOS version, architecture types, and most binaries. **Clutch is meant only for educational purposes and security research.**

Clutch requires a jailbroken iOS device with version 12.0 or greater (arm64 only).

Supports both **rootful** (unc0ver, checkra1n) and **rootless** (Dopamine, palera1n) jailbreaks.

# Usage

```
Clutch [OPTIONS]
-b --binary-dump     Only dump binary files from specified bundleID
-d --dump            Dump specified bundleID into .ipa file
-i --print-installed Print installed application
--clean              Clean /var/tmp/clutch directory
--version            Display version and exit
-? --help            Display this help and exit
```

Clutch may encounter `Segmentation Fault: 11` when dumping apps with a large number of frameworks. Increase your device's maximum number of open file descriptors with `ulimit -n 512` (default is 256).


# Building

## Requirements

* Xcode (install from [App Store](https://itunes.apple.com/us/app/xcode/id497799835?mt=12) or from [Apple's developer site](http://adcdownload.apple.com/Developer_Tools/Xcode_8.2.1/Xcode_8.2.1.xip))
* Xcode command line tools: `xcode-select --install` (or from [Apple's developer site](http://adcdownload.apple.com/Developer_Tools/Command_Line_Tools_macOS_10.12_for_Xcode_8.2/Command_Line_Tools_macOS_10.12_for_Xcode_8.2.dmg))

## Disable SDK code signing requirement

```sh
killall Xcode
cp /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/SDKSettings.plist ~/
sudo /usr/libexec/PlistBuddy -c "Set :DefaultProperties:CODE_SIGNING_REQUIRED NO" /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/SDKSettings.plist
sudo /usr/libexec/PlistBuddy -c "Set :DefaultProperties:AD_HOC_CODE_SIGNING_ALLOWED YES" /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/SDKSettings.plist
```

Note that if you update Xcode you may need to run these commands again.

## Compiling

### Xcode

```sh
xcodebuild clean build
```

### CMake

```sh
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../cmake/iphoneos.toolchain.cmake ..
make -j$(sysctl -n hw.logicalcpu)
```

## Installation

### Download Pre-built Binary

Download the latest release from [GitHub Actions](../../actions) or the [Releases](../../releases) page.

### Rootless Jailbreaks (Dopamine, palera1n)

For rootless jailbreaks, the binary must be installed to `/var/jb/usr/bin/`:

```sh
# Copy binary to device
scp ./Clutch root@<your.device.ip>:/var/jb/usr/bin/Clutch
scp ./Clutch.entitlements root@<your.device.ip>:/var/jb/usr/bin/

# SSH into device and sign with ldid
ssh root@<your.device.ip>
ldid -S/var/jb/usr/bin/Clutch.entitlements /var/jb/usr/bin/Clutch
chmod 755 /var/jb/usr/bin/Clutch
```

### Rootful Jailbreaks (unc0ver, checkra1n)

```sh
# Copy binary to device
scp ./Clutch root@<your.device.ip>:/usr/bin/Clutch
scp ./Clutch.entitlements root@<your.device.ip>:/usr/bin/

# SSH into device and sign with ldid
ssh root@<your.device.ip>
ldid -S/usr/bin/Clutch.entitlements /usr/bin/Clutch
chmod 755 /usr/bin/Clutch
```

If you are using [iproxy](http://iphonedevwiki.net/index.php/SSH_Over_USB), add `-P 2222` to the scp commands.

### Using the Install Script

You can also use the included `install.sh` script on your device:

```sh
# Copy files to device
scp ./Clutch ./Clutch.entitlements ./install.sh root@<your.device.ip>:/tmp/

# SSH and run installer
ssh root@<your.device.ip>
cd /tmp && chmod +x install.sh && ./install.sh
```

### Troubleshooting

If you see `Killed: 9` or `zsh: killed`, the binary is not properly signed:

1. Make sure you copied `Clutch.entitlements` to the device
2. Re-sign with ldid: `ldid -S/path/to/Clutch.entitlements /path/to/Clutch`
3. For unc0ver, also run: `inject /usr/bin/Clutch`

# Licenses

Clutch uses the following libraries under their respective licenses.

* [optool](https://github.com/alexzielenski/optool) by Alex Zielenski
* [ZipArchive](https://github.com/mattconnolly/ZipArchive/) by Matt Connolly, Edward Patel, et al.
* [MiniZip](http://www.winimage.com/zLibDll/minizip.html) by Gilles Vollant and Mathias Svensson.

# Thanks

Clutch would not be what it is without these people:

* dissident - The original creator of Clutch (pre 1.2.6)
* Nighthawk - Code contributor (pre 1.2.6)
* Rastignac - Inspiration and genius
* TheSexyPenguin - Inspiration

# Contributors

* [iT0ny](https://github.com/iT0ny)
* [ttwj](https://github.com/ttwj)
* [NinjaLikesCheez](https://github.com/NinjaLikesCheez)
* [Tatsh](https://github.com/Tatsh)
* [C0deH4cker](https://github.com/C0deH4cker)
* [DoubleDoughnut](https://github.com/DoubleDoughnut)
* [iD70my](https://github.com/iD70my)
* [OdNairy](https://github.com/OdNairy)
* [palmerc](https://github.com/palmerc)
* [jack980517](https://github.com/jack980517)

# Copyright

© [Kim Jong-Cracks](http://cracksby.kim) 1819-2017
