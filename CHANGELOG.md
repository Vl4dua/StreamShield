# Changelog

## 1.0.1-alpha

This alpha release includes a round of stability and compatibility fixes ahead of a more polished stable update.

### Fixed

- Reduced false positives in geo detection on non-geo pages.
- Prevented masking logic from altering real page resource URLs such as image and link attributes.
- Improved compatibility of the autofill guard to avoid breaking or freezing forms on complex sites.
- Reworked the panic blur behavior to use a fullscreen overlay instead of relying on page-level body filters.
- Improved repeated autofill protection application on dynamic pages and SPA-style layouts.
- Updated popup wording for the autofill protection section.

### Known Issues

- Browser-native password or account suggestion panels may still appear on some sites because Chrome and password managers can ignore page hints.
- Some edge cases may still exist on unusual layouts, heavily scripted dashboards, or sites that rewrite forms after load.
- Additional tuning is still needed before treating this build as a fully stable release.

### Status

- Recommended for internal testing and limited real-world use.
- Not yet considered the final stable `1.0.1` release.
