# SecurityValidator

SecurityValidator is a Python-based [AutoPkg](https://github.com/autopkg/autopkg) processor for Mac admins everywhere to help ensure that your users are installing exactly what they think they are.

### Why Make This Tool?

Even though Macs are generally more secure than other computing platforms, that does not mean that there are zero security risks. Remember when the Sparkle framework was compromised? Even legitimate, well-intentioned apps were introducing vulnerabilities if they used Sparkle. As a result, more and more InfoSec departments want some sort of assurance that the software being installed on company devices is legitimate and won't introduce risk to the company.

At the same time, more and more Mac admins are looking to automate the process of finding new installer packages, repackaging them if necessary, and uploading them to their company's MDM/Munki server so they can spend their time on other things. The new release of software never ends, so automating this is key to an admin's sanity.

These two goals seem as though they are diametrically opposed to each other. Tools like AutoPkg or Installomator make it easy to keep software up to date, but by default only provide limited recipe-specific security validation. You can use tools like [Suspicious Package](https://mothersruin.com/software/SuspiciousPackage) and [Apparency](https://mothersruin.com/software/Apparency) to give InfoSec the peace of mind they crave, but they slow down or completely break your automation workflows.

Enter SecurityValidator.

SecurityValidator is an AutoPkg processor that replicates the functionality of Suspicious Package and Apparency using native macOS tools, all within your existing AutoPkg-based workflows. In short, it makes sure that the .pkg or the app within a .dmg is notarized and is signed by the correct Developer ID. For app bundles, it goes a step further and inspects all of the macOS-specific components as well, including third party frameworks such as Sparkle. When inserted into an existing AutoPkg workflow before the step where you upload the newly built package to your software repository, it will ensure that your entire recipe stops if anything out of the ordinary is detected.

## **Key Features**

* **Gatekeeper & Notarization Validation:** Leverages native `spctl` to ensure the installer has been notarized by Apple and hasn't been revoked.
* **Deep Component Scanning:** Recursively inspects every Mach-O binary and nested bundle (`.framework`, `.appex`, etc.) within an application to verify internal signing consistency. Interpreted scripts and non-native resource files are intentionally excluded, as macOS code signing does not apply to them and enforcing signatures would produce false positives.
* **Exploit Mitigation:**
  * **Symlink Escape Detection:** Prevents "Time-of-Check to Time-of-Use" (TOCTOU) attacks by ensuring symlinks don't point to sensitive system directories (e.g., `/etc` or `/private/var`).
  * **Permission Hardening:** Automatically flags dangerous file modes, such as `World-Writable` files or `Setuid/Setgid` bits that could lead to Local Privilege Escalation (LPE).
* **Performant by Design:** Uses magic-byte header analysis for Mach-O detection, ensuring that even massive applications like Google Chrome or Microsoft Teams are scanned in seconds.
* **Developer ID Allowlisting:** Matches all components against a curated `team_ids.txt` file, allowing for flexible support of third-party frameworks while blocking unknown actors.


## Quick Start

1. Add your trusted Developer IDs to `team_ids.txt`
2. Insert `SecurityValidator` into your AutoPkg recipe after download and before upload
3. Run AutoPkg normally

If any validation fails, the recipe stops immediately and nothing is uploaded.

## Threat Model & Scope

SecurityValidator is designed to detect **supply-chain and packaging risks** in macOS software automation workflows, including:

- Tampered or replaced installer artifacts
- Unsigned or foreign-signed native binaries
- Symlink-based filesystem escape attacks
- Dangerous file permissions that could lead to local privilege escalation

It does **not** attempt to:

- Perform malware detection or behavioral analysis
- Replace antivirus or EDR solutions
- Guarantee that a trusted vendor’s software is free of vulnerabilities

SecurityValidator answers the question:
**“Is this installer exactly what we expect it to be, and is it cryptographically trustworthy?”**

## Platform Requirements & Limitations

- SecurityValidator should be run on the same CPU architecture as the software being validated.
  - Apple Silicon hosts cannot mount x86-only DMGs without Rosetta 2 installed.
    - On a clean-install Apple Silicon Mac without Rosetta, the** `hdiutil` **command will fail when attempting to mount an Intel-based disk image.
  - Intel hosts cannot mount Apple Silicon–only DMGs.

This processor is intended to be used in CI or AutoPkg environments that match the target platform of the software being built. Since macOS Tahoe is the last version of macOS that will support Intel Macs, this should not be an issue for very long - but it is something to be aware of.

## Requirements

* AutoPkg must already be installed and configured
* This repo should be cloned and live inside of the ~/Library/AutoPkg/RecipeRepos folder on the computer running your AutoPkg automations
* The team_ids.txt file

## How To Use This Processor

### Before You Begin

The first thing you need to do is make sure that any Developer ID used by the applications you run AutoPkg automations for is saved in the team_ids.txt file. The file needs one ID per line, and to save you some frustration later, you can add a hashed comment after the ID so you can put the name of the developer. How do you get those Developer IDs? If you already have Suspicious Package and/or Apparency installed, you can use them. The best way is to run this command on an app you already have installed in Terminal:

`find "/Applications/App.app" -type f -perm -111 -exec codesign -dv {} + 2>&1 | grep "TeamIdentifier" | sed 's/TeamIdentifier=//' | sort -u`

This will output all the unique Developer IDs that are found in the components of the application. If you use this method and want to confirm who the Developer ID belongs to, you can do a web search for '[ID] Developer ID'. Using SecurityValidation without having added the IDs to the txt file will cause the processor to fail.

Finally, you should save team_ids.txt in a location that is not in your AutoPkg cache to reduce chances it gets deleted accidentally.

### Using The Processor

The processor is designed to be run either as part of a larger AutoPkg automation or as a stand alone script. The processor accepts three arguments:

* Path to the **folder** that contains the .pkg/.dmg file downloaded by AutoPkg (for most this will be `~/Library/AutoPkg/Caches/[recipe name]/downloads`)
* Path to the team_ids.txt file
* AutoPkg recipe name (optional)

If you want to run the processor as a standalone script, you will run the following commands in Terminal:

`PYTHONPATH="/Library/AutoPkg" /usr/local/autopkg/python /path/to/SecurityValidator.py --file_path /path/to/downloaded/installer --id_file /path/to/team_ids.txt`

When you run the processor on its own, it will tell you whether the .pkg/.app has been successfully notarized by Apple or not, and if all found Developer ID(s) exist in team_ids.txt.

If you build your AutoPkg recipes in yaml, you will insert the below code **before** the MunkiImport/JamfPackageUploader/etc processors - this way if the installer does not pass the checks, the recipe stops and the malicious installer is not uploaded to your repository:

```
Process:
  - Processor: SecurityValidator
    Arguments:
      # Use the built-in variable from the Download step
      file_path: "%pathname%"
      id_file: "/path/to/your/team_ids.txt"
      recipe_name: "%NAME%"
      # Optional: toggle security strictness
      fail_on_world_writable: true
```

If you write your recipes using XML, add the following XML block to a local override in a similar location as you would in a yaml recipe (after the installer is downloaded but before it is uploaded anywhere):

```
<dict>
    <key>Processor</key>
    <string>SecurityValidator</string>
    <key>Arguments</key>
    <dict>
        <key>file_path</key>
        <string>%RECIPE_CACHE_DIR%/%NAME%/downloads</string>
        <key>id_file</key>
        <string>/path/to/your/team_ids.txt</string>
        <key>fail_on_world_writable</key>
        <true/>
    </dict>
</dict>
```
