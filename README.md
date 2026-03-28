# StreamShield

**Stream with confidence. Browse without leaking sensitive data.**

StreamShield is a privacy-focused browser extension designed for streamers, creators, and anyone who shares their screen live. It helps reduce accidental exposure by masking sensitive information directly on the page, in real time.

Whether you are live on Twitch, recording a video, or sharing your screen in a call, StreamShield adds an extra layer of protection between your session and the information you do not want visible.

## Why StreamShield

Going live means one distracted second can expose more than expected. StreamShield was built to make that less likely by keeping sensitive details hidden while you browse normally.

It is meant to feel simple in use:
- enable it
- choose what to protect
- browse as usual

## What It Can Hide

- IP addresses
- Email addresses
- Phone numbers
- Physical addresses
- Geo and ISP information
- User-Agent strings
- Sensitive visible inputs

## Main Features

- Real-time masking across pages
- Independent toggles for each protection type
- Domain whitelist support
- Click-to-hide tool for manual control
- Screenshot mode
- Panic blur mode
- Clean popup UI with light and dark themes

## Privacy First

StreamShield is intentionally lightweight and local-first.

- No analytics
- No remote tracking
- No external backend
- No bundled secrets

## Project Structure

- `manifest.json`
- `background.js`
- `content.js`
- `content.css`
- `popup.html`
- `popup.js`
- `popup.css`
- `icons/`

## Load It Locally

### Chrome / Edge

1. Open the extensions page.
2. Enable Developer Mode.
3. Click `Load unpacked`.
4. Select this project folder.

## Version

Current release: `1.0.0`

## Status

`v1.0.0` is the first public version. The extension is already usable and stable for real-world browsing and streaming, with some edge cases still open for future refinement, especially around geo-data detection on unusual layouts.

## License

Released under the MIT License. See [LICENSE](./LICENSE).
