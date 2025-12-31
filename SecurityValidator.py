#!/usr/local/autopkg/python

from autopkglib import Processor, ProcessorError
import subprocess
import os
import re
import sys
import tempfile
import shutil
import glob
import time
import stat

__all__ = ["SecurityValidator"]

class SecurityValidator(Processor):
    description = ("Hardens AutoPkg security by verifying Apple Notarization "
                   "and ensuring all native macOS components match trusted Team IDs.")
    
    input_variables = {
        "file_path": {
            "required": True,
            "description": "Path to the .pkg, .dmg or .app to be analyzed."
        },
        "id_file": {
            "required": True,
            "description": "Path to the trusted_ids.txt file containing allowed Team IDs."
        },
        "recipe_name": {
            "required": False,
            "description": "The %NAME% variable to help differentiate architecture files."
        },
        "verbose_logging": {
            "required": False,
            "default": False,
            "description": "If true, logs every unsigned script found."
        },
        "fail_on_world_writable": {"required": False, "default": True},
        "fail_on_setuid": {"required": False, "default": True},
        "fail_on_symlink_escape": {"required": False, "default": True},
        "allowed_symlink_prefixes": {"required": False, "default": []},
    }
    output_variables = {}

    def check_file_permissions(self, root_path, fail_on_world_writable=True, fail_on_setuid=True):
        setuid, setgid, world = [], [], []

        for dirpath, _, filenames in os.walk(root_path):
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue

                if st.st_mode & stat.S_ISUID:
                    setuid.append(full)
                if st.st_mode & stat.S_ISGID:
                    setgid.append(full)
                if st.st_mode & stat.S_IWOTH:
                    world.append(full)

        if (setuid or setgid) and fail_on_setuid:
            raise ProcessorError(f"Setuid/setgid files found: {(setuid+setgid)[0]}")
        if world and fail_on_world_writable:
            raise ProcessorError(f"World-writable files found: {world[0]}")

        if (setuid or setgid or world):
            self.output(f"WARNING: permissions issues found "
                        f"(setuid={len(setuid)}, setgid={len(setgid)}, world={len(world)})")

    def check_symlink_escapes(self, bundle_root, fail_on_escape=True, allow_prefixes=None):
        allow_prefixes = [os.path.realpath(p) for p in (allow_prefixes or [])]
        real_bundle = os.path.realpath(bundle_root)

        for root, dirs, files in os.walk(bundle_root, followlinks=False):
            for name in dirs + files:
                full = os.path.join(root, name)
                if os.path.islink(full):
                    try:
                        target = os.path.realpath(full)
                    except OSError:
                        target = "unresolvable"

                    if not target.startswith(real_bundle):
                        if not any(target.startswith(p) for p in allow_prefixes):
                            if fail_on_escape:
                                raise ProcessorError(f"Symlink escape: {full} -> {target}")
                            self.output(f"WARNING: Symlink escape {full} -> {target}")

    # ---------- Utility helpers ----------

    def get_trusted_ids(self, file_path):
        ids = []
        with open(os.path.expanduser(file_path)) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    ids.append(line)
        return ids
   
    def parse_bool(self, val):
        """Helper to handle AutoPkg strings vs Booleans."""
        if isinstance(val, bool):
            return val
        return str(val).lower() in ("true", "yes", "1")

    def is_macho_binary(self, path):
        if not os.path.isfile(path) or os.path.islink(path):
            return False
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                # Check for Mach-O Magic (Little/Big Endian & 32/64 bit & Fat)
                return magic in [b'\xca\xfe\xba\xbe', b'\xce\xfa\xed\xfe', 
                                b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']
        except:
            return False

    def resolve_target_path(self, path, recipe_name=None):
        path = os.path.expanduser(path)
        if os.path.isfile(path):
            return path

        matches = []
        for ext in (".pkg", ".dmg", ".app"):
            for f in os.listdir(path):
                if f.lower().endswith(ext):
                    matches.append(os.path.join(path, f))

        if not matches:
            raise ProcessorError(f"No installer found in {path}")

        if recipe_name:
            for m in matches:
                if recipe_name.lower() in os.path.basename(m).lower():
                    return m
        return matches[0]

    # ---------- Main ----------

    def main(self):
        fail_on_world = self.parse_bool(self.env.get("fail_on_world_writable", True))
        fail_on_setuid = self.parse_bool(self.env.get("fail_on_setuid", True))
        fail_on_symlink = self.parse_bool(self.env.get("fail_on_symlink_escape", True))
        recipe_name = self.env.get("recipe_name") or self.env.get("NAME")
        target = self.resolve_target_path(self.env["file_path"], recipe_name)
        trusted_ids = self.get_trusted_ids(self.env["id_file"])

        self.verbose = str(self.env.get("verbose_logging", False)).lower() in ("1","true","yes")
        allow_symlinks = self.env.get("allowed_symlink_prefixes", [])

        mountpoint = None
        try:
            # ---- DMG handling ----
            if target.lower().endswith(".dmg"):
                mountpoint = tempfile.mkdtemp(prefix="autopkg_dmg_")
                res = subprocess.run(
                    ["hdiutil", "attach", target, "-readonly", "-nobrowse", "-quiet", "-mountpoint", mountpoint]
                )
                if res.returncode != 0:
                    raise ProcessorError(f"Failed to mount DMG: {target}")

                apps = glob.glob(os.path.join(mountpoint, "*.app"))
                if not apps:
                    raise ProcessorError("No .app found inside DMG")
                target = apps[0]

            # ---- Notarization ----
            assess = "install" if target.endswith(".pkg") else "execute"
            spctl = subprocess.run(
                ["/usr/sbin/spctl", "--assess", "--type", assess, "-vv", target],
                capture_output=True, text=True
            )
            if spctl.returncode != 0:
                raise ProcessorError(f"Security assessment failed: {spctl.stderr}")
            self.output("Gatekeeper/Notarization: PASSED")

            # ---- PKG Team ID ----
            if target.endswith(".pkg"):
                pkg_info = subprocess.run(["/usr/sbin/pkgutil", "--check-signature", target], capture_output=True, text=True)
                team_id_match = re.search(r"Developer ID Installer: .*\(([A-Z0-9]{10})\)", pkg_info.stdout)
                if not team_id_match or team_id_match.group(1) not in trusted_ids:
                    raise ProcessorError(f"Untrusted PKG Team ID: {team_id_match.group(1) if team_id_match else 'None'}")
                self.output("Installer Team ID: PASSED")

            # ---- APP deep scan ----
            if target.endswith(".app"):
                self.check_file_permissions(target, fail_on_world, fail_on_setuid)
                self.check_symlink_escapes(target, fail_on_symlink, allow_symlinks)

                team_re = re.compile(r"TeamIdentifier=([A-Z0-9]{10})")
                SKIP_DIRS = ("_CodeSignature", "_MASReceipt", "Resources")

                for root, dirs, files in os.walk(target):
                    if any(s in root for s in SKIP_DIRS):
                        continue

                    for d in list(dirs):
                        if d.endswith((".framework",".appex",".plugin",".bundle")):
                            path = os.path.join(root, d)
                            cs = subprocess.run(["codesign","-dv",path], capture_output=True, text=True)
                            if cs.returncode != 0:
                                raise ProcessorError(f"codesign failed: {path}")
                            m = team_re.search(cs.stderr)
                            if not m or m.group(1) not in trusted_ids:
                                raise ProcessorError(f"Untrusted Team ID in {path}")
                            dirs.remove(d)

                    for f in files:
                        full = os.path.join(root, f)
                        if self.is_macho_binary(full):
                            cs = subprocess.run(["codesign","-dv",full], capture_output=True, text=True)
                            m = team_re.search(cs.stderr)
                            if not m or m.group(1) not in trusted_ids:
                                raise ProcessorError(f"Untrusted native binary: {full}")

                self.output("Component signatures: PASSED")

        finally:
            if mountpoint:
                subprocess.run(["hdiutil","detach",mountpoint,"-force","-quiet"])
                shutil.rmtree(mountpoint, ignore_errors=True)

        self.output("Security Validation Successful.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--file_path")
        p.add_argument("--id_file")
        p.add_argument("--recipe_name")
        args = p.parse_args()

        proc = SecurityValidator()
        proc.env = vars(args)
        proc.output = lambda x: print(x)

        try:
            proc.main()
        except ProcessorError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        PROCESSOR = SecurityValidator()
        PROCESSOR.execute_shell()