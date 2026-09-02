# RadarAI

RadarAI is a standalone GTK 4 Flatpak for MechOS and compatible Linux systems. It scans available system-health information, explains detected problems, saves privacy-sanitized reports, and can submit reviewed reports to the MechOS GitHub repository.

## Safety model

- no root access
- no host write access
- no personal-folder access
- GitHub token kept in memory for the current session only
- no direct deployment of AI-generated changes
- Copilot fixes must be delivered as pull requests and pass review

## Build

```bash
flatpak install -y flathub org.gnome.Platform//48 org.gnome.Sdk//48
flatpak-builder --force-clean --repo=repo build-dir io.mechgod.RadarAI.yml
flatpak build-bundle repo RadarAI.flatpak io.mechgod.RadarAI
```

The included GitHub Actions workflow also builds the Flatpak bundle automatically.

## MechOS integration

Copy the contents of `mechos-repository-kit/` into the root of the MechOS source repository. This adds RadarAI issue intake, Copilot repair guidance, pull-request validation and a monthly hotfix review queue.
