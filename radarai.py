#!/usr/bin/env python3
import hashlib, json, os, platform, shutil, socket, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk

APP_ID = "io.mechgod.RadarAI"

def read_text(path, limit=200000):
    try:
        return Path(path).read_text(errors="replace")[:limit]
    except (OSError, PermissionError):
        return ""

def redact(value):
    home = str(Path.home())
    value = value.replace(home, "~")
    value = value.replace(socket.gethostname(), "[hostname]")
    return value

def scan():
    findings = []
    def add(level, area, title, detail):
        findings.append({"level": level, "area": area, "title": title, "detail": redact(detail)})
    mem = {}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" in line:
            k, v = line.split(":", 1); mem[k] = int(v.strip().split()[0])
    total, avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
    if total:
        pct = 100 * avail / total
        add("warning" if pct < 10 else "ok", "Memory", "Available memory", f"{pct:.1f}% available")
    usage = shutil.disk_usage("/")
    free = 100 * usage.free / usage.total
    add("critical" if free < 5 else "warning" if free < 12 else "ok", "Storage", "Root filesystem space", f"{free:.1f}% free")
    load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0
    cpus = os.cpu_count() or 1
    add("warning" if load > cpus * 1.5 else "ok", "CPU", "One-minute system load", f"{load:.2f} across {cpus} logical CPUs")
    temps = []
    for p in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            c = float(p.read_text().strip()) / 1000
            if 0 < c < 150: temps.append(c)
        except (OSError, ValueError): pass
    if temps:
        hottest = max(temps)
        add("critical" if hottest >= 95 else "warning" if hottest >= 85 else "ok", "Thermal", "Highest reported temperature", f"{hottest:.1f}°C")
    else:
        add("info", "Thermal", "Temperature sensors unavailable", "The Flatpak sandbox could not read a supported thermal sensor.")
    errors = []
    for path in ("/sys/fs/pstore",):
        try: errors.extend(x.name for x in Path(path).iterdir() if x.is_file())
        except OSError: pass
    add("warning" if errors else "ok", "Kernel", "Previous crash records", ", ".join(errors[:10]) if errors else "No readable pstore crash records found")
    signature_source = "|".join(sorted(f'{x["area"]}:{x["title"]}:{x["level"]}' for x in findings))
    return {
        "schema": 2, "app": "RadarAI 0.2.0", "time": datetime.now(timezone.utc).isoformat(),
        "fingerprint": hashlib.sha256(signature_source.encode()).hexdigest()[:16],
        "system": {"os": platform.platform(), "kernel": platform.release(), "machine": platform.machine()},
        "findings": findings,
        "limitations": ["Protected journals and raw SMART/NVMe health may be unavailable inside a standalone Flatpak."]
    }

class Window(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="RadarAI")
        self.set_default_size(900, 680); self.report = None
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(18); box.set_margin_bottom(18); box.set_margin_start(18); box.set_margin_end(18)
        title = Gtk.Label(xalign=0); title.set_markup("<span size='xx-large' weight='bold'>RadarAI</span>\nSystem health and GitHub problem reporting")
        box.append(title)
        controls = Gtk.Box(spacing=8)
        scan_btn = Gtk.Button(label="Scan system"); scan_btn.add_css_class("suggested-action"); scan_btn.connect("clicked", self.on_scan)
        save_btn = Gtk.Button(label="Save report"); save_btn.connect("clicked", self.on_save)
        controls.append(scan_btn); controls.append(save_btn); box.append(controls)
        self.status = Gtk.Label(label="Ready to scan", xalign=0); box.append(self.status)
        self.view = Gtk.TextView(editable=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD)
        scroll = Gtk.ScrolledWindow(vexpand=True); scroll.set_child(self.view); box.append(scroll)
        grid = Gtk.Grid(column_spacing=8, row_spacing=8)
        self.repo = Gtk.Entry(placeholder_text="owner/repository")
        self.branch = Gtk.Entry(placeholder_text="main"); self.branch.set_text("main")
        self.token = Gtk.PasswordEntry(placeholder_text="Fine-grained GitHub token (session only)")
        self.copilot = Gtk.CheckButton(label="Ask GitHub Copilot to create a fix pull request")
        self.copilot.set_active(True)
        send = Gtk.Button(label="Review and send to MechOS source"); send.connect("clicked", self.on_submit)
        grid.attach(Gtk.Label(label="Repository", xalign=0),0,0,1,1); grid.attach(self.repo,1,0,1,1)
        grid.attach(Gtk.Label(label="Base branch", xalign=0),0,1,1,1); grid.attach(self.branch,1,1,1,1)
        grid.attach(Gtk.Label(label="Token", xalign=0),0,2,1,1); grid.attach(self.token,1,2,1,1)
        grid.attach(self.copilot,1,3,1,1); grid.attach(send,1,4,1,1)
        box.append(grid); self.set_child(box)
    def render(self):
        self.view.get_buffer().set_text(json.dumps(self.report, indent=2) if self.report else "No report yet.")
    def on_scan(self, _):
        self.report = scan(); self.render()
        bad = sum(x["level"] in ("warning","critical") for x in self.report["findings"])
        self.status.set_text(f"Scan complete — {bad} item(s) need attention")
        if bad: self.get_application().send_notification("health", Gio.Notification.new("RadarAI found system health warnings"))
    def on_save(self, _):
        if not self.report: self.on_scan(None)
        folder = Path(GLib.get_user_data_dir()) / APP_ID / "reports"; folder.mkdir(parents=True, exist_ok=True)
        path = folder / (datetime.now().strftime("radarai-%Y%m%d-%H%M%S.json")); path.write_text(json.dumps(self.report, indent=2))
        self.status.set_text(f"Saved locally: {path}")
    def on_submit(self, _):
        if not self.report: self.on_scan(None)
        repo, token = self.repo.get_text().strip(), self.token.get_text().strip()
        if repo.count("/") != 1 or not token: self.status.set_text("Enter a repository and token first"); return
        dialog = Gtk.AlertDialog(message="Submit this sanitized report to GitHub?", detail="Review the report above. RadarAI will create one issue labeled radarai and diagnostic.", buttons=["Cancel","Submit"], cancel_button=0, default_button=1)
        dialog.choose(self, None, self._confirmed, (repo, token, self.branch.get_text().strip() or "main", self.copilot.get_active()))
    def _confirmed(self, dialog, result, data):
        try:
            if dialog.choose_finish(result) != 1: return
            repo, token, branch, use_copilot = data
            warnings = [x for x in self.report["findings"] if x["level"] in ("warning","critical")]
            instructions = "Investigate this sanitized MechOS diagnostic. Make the smallest source-level fix, add a regression test, run repository validation, and open a pull request. Do not weaken security, disable checks, or commit generated binaries. Mark the PR for the monthly-hotfix queue; do not deploy directly."
            payload = {
                "title": f"[RadarAI:{self.report['fingerprint']}] {len(warnings)} software/system finding(s)",
                "body": "## Sanitized RadarAI report\n\nThis report was reviewed by the user before submission.\n\n```json\n" + json.dumps(self.report, indent=2) + "\n```\n\n## Repair requirements\n" + instructions,
            }
            if use_copilot:
                payload["assignees"] = ["copilot-swe-agent[bot]"]
                payload["agent_assignment"] = {"target_repo": repo, "base_branch": branch, "custom_instructions": instructions, "custom_agent": "", "model": ""}
            req = urllib.request.Request(f"https://api.github.com/repos/{repo}/issues", data=json.dumps(payload).encode(), method="POST", headers={"Authorization": f"Bearer {token}", "Accept":"application/vnd.github+json", "X-GitHub-Api-Version":"2022-11-28", "User-Agent":"RadarAI"})
            with urllib.request.urlopen(req, timeout=20) as response: result_data = json.load(response)
            action = " and assigned to Copilot" if use_copilot else ""
            self.status.set_text(f"GitHub issue created{action}: {result_data.get('html_url','success')}")
        except Exception as exc: self.status.set_text(f"GitHub submission failed: {exc}")

class App(Gtk.Application):
    def __init__(self): super().__init__(application_id=APP_ID)
    def do_activate(self): Window(self).present()

if __name__ == "__main__": App().run()
