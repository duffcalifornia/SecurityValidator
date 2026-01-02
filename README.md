# SecurityValidator

SecurityValidator is a Python-based [AutoPkg](https://github.com/autopkg/autopkg) processor for Mac admins everywhere to help ensure that your users are installing exactly what they think they are by validating installer trust as part of an automated workflow.

## What SecurityValidator Does and Does Not Do

What the processor does:

* Confirm that the installer is notarized by Apple
* For .pkg installers, confirms the observed Developer ID matches the expected Developer ID
* For .dmg installers, it inspects all native macOS components of the app to confirm that the observed Developer ID for every component matches the expected Developer ID

What the processor does not do:

* Malware detection
* Behavioral analysis
* Act as an EDR/antivirus replacement

## Quick Start

1. Add SecurityValidator to your AutoPkg/RecipeRepos folder
2. Save `team_ids.txt` somewhere on the machine running your automations
3. Add your trusted Developer IDs to `team_ids.txt`
4. Insert `SecurityValidator` into your AutoPkg recipe after download and before upload
5. Run AutoPkg normally

If any validation fails, the recipe stops immediately and nothing is uploaded.

An example of how to use the processor:

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
