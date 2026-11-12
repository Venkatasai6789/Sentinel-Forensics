# Sentinel Forensics --- Mobile Design System

> **Status:** Initial visual specification derived from the supplied
> seven-screen mobile UI reference.\
> **Purpose:** A single source of truth for implementing a consistent,
> professional Android interface.\
> **Platform target:** Android; suitable for Jetpack Compose and
> Material 3.\
> **Token confidence:** Colors, dimensions, and radii below are
> carefully estimated from the raster reference, not extracted from
> original design files. Validate them against the source Figma file if
> one becomes available.

------------------------------------------------------------------------

## Overview

### Design intent

Use the reference's calm, low-noise interface as the visual starting
point: white surfaces, cool neutral backgrounds, restrained accent
colors, compact but readable information, and repeatable card patterns.
For **Sentinel Forensics**, preserve the clarity and component
consistency---not the VPN-specific wording, subscription model, or
unsupported security claims.

The resulting product should feel like a dependable digital-forensics
utility: measured, evidence-led, clear about status, and easy to
navigate under pressure. Avoid decorative gradients, excessive shadows,
novelty illustrations, and alarmist use of red.

### Core principles

1.  **Clarity before decoration.** The action, current status, and next
    step should be obvious.
2.  **One component, one rule.** Shared components must use the same
    spacing, typography, radius, icon size, and state colors throughout
    the app.
3.  **Status is never color-only.** Pair a color with text, an icon, or
    both.
4.  **Evidence over drama.** Use warning and critical treatments only
    when a finding warrants them.
5.  **Honest system states.** Distinguish `Not scanned`, `Scanning`,
    `No issues detected`, `Potential risk`, `Scan failed`,
    `Unavailable offline`, and `Permission required`.
6.  **Local-first clarity.** When a feature runs locally, say so
    accurately. Do not imply cloud checks or live intelligence when the
    device is offline.
7.  **Native-feeling interactions.** Use Android back behavior,
    accessible touch targets, system bars, and Material 3 interaction
    patterns.

### Reference screen inventory

  -----------------------------------------------------------------------
  Ref. screen             Visible pattern         Reusable design pattern
  ----------------------- ----------------------- -----------------------
  1\. Main                Header, enabled switch, Screen header, status
  protection/status       selected region,        row, setting row,
                          settings row, usage     metric card, compact
                          summary, chart, alerts  bar chart, empty state
                          panel                   

  2\. Full protection     Large centered          Status hero,
  overview                shield/status emblem,   feature/service row,
                          heading, supporting     status badge, bottom
                          text, stacked service   navigation
                          rows, bottom navigation 

  3\. Region selection    Search field, automatic Search field,
                          selection, grouped      selectable list row,
                          favorites and all       section label,
                          locations, selected     selection/favorite
                          check, favorite star    affordances

  4\. Settings            Grouped settings card,  Settings group,
                          selectable options,     radio/choice row,
                          ignored-network list,   removable chip/list
                          add action, kill-switch item, switch row
                          toggle                  

  5\.                     Page title, segmented   Profile header,
  Profile/subscription    tabs, subscription card segmented control,
                          with feature checklist  subscription/plan card,
                                                  benefit row

  6\. Verification code   Focused title, helper   Focused task
                          text, code-entry flow,  sheet/page, OTP input,
                          dismiss/close action    inline
                                                  helper/error/success
                                                  states

  7\. Identity monitoring Service header with     Feature control row,
                          switch, two linked      navigation row, threat
                          feature rows, threat    metric card, status
                          summary cards           indicator
  -----------------------------------------------------------------------

The screenshot demonstrates layout and styling, but does not define
every interaction, screen state, responsive rule, or exact token. The
rules below formalize these gaps for implementation.

------------------------------------------------------------------------

## Colors

### Color palette

Use these as initial tokens. The reference image has been compressed and
displayed against a grey canvas, so the values are approximations
intended to create a coherent system.

  --------------------------------------------------------------------------
  Token                      Value                   Usage
  -------------------------- ----------------------- -----------------------
  `color.primary`            `#4F72E8`               Selected tab, primary
                                                     action, selected
                                                     navigation or location
                                                     state

  `color.primaryPressed`     `#3F60CF`               Pressed primary
                                                     controls

  `color.primaryContainer`   `#E9EEFF`               Selected row or
                                                     low-emphasis active
                                                     background

  `color.onPrimary`          `#FFFFFF`               Text/icons on primary
                                                     fills

  `color.background`         `#F5F6F8`               App-level background

  `color.surface`            `#FFFFFF`               Cards, sheets, inputs,
                                                     navigation surfaces

  `color.surfaceSubtle`      `#F2F4F7`               Secondary choice rows
                                                     and quiet control
                                                     backgrounds

  `color.surfaceSelected`    `#EEF1FF`               Selected option
                                                     backgrounds

  `color.border`             `#E6E9EF`               Subtle outlines and
                                                     dividers

  `color.textPrimary`        `#17191F`               Headings and primary
                                                     body content

  `color.textSecondary`      `#747B87`               Helper text, captions,
                                                     metadata

  `color.textTertiary`       `#969DA8`               Disabled labels and
                                                     low-priority metadata

  `color.success`            `#25A653`               Active, verified,
                                                     completed, safe states

  `color.successContainer`   `#E8F7ED`               Low-emphasis success
                                                     badge background

  `color.warning`            `#B7791F`               Caution and
                                                     review-needed states

  `color.warningContainer`   `#FFF4D9`               Warning background

  `color.danger`             `#C83E4D`               Confirmed high-risk
                                                     state, destructive
                                                     action, failure

  `color.dangerContainer`    `#FCEBED`               Low-emphasis danger
                                                     background

  `color.info`               `#4477C8`               Informational status
                                                     and neutral guidance

  `color.overlay`            `#111827` at 40%        Modal scrim
                             opacity                 
  --------------------------------------------------------------------------

### Color rules

-   The primary blue communicates **selection and primary action**; it
    must not mean "safe."
-   Green means an explicit positive state such as `Enabled`,
    `Verified`, or `Completed`. Do not use green for an unscanned item.
-   Amber means `Review` or `Uncertain`; red means `High risk`,
    `Blocked`, or a meaningful failure.
-   For scan results, always show a written severity label and
    supporting evidence beside the colored state.
-   Use neutral surfaces for most content. Do not place every card on a
    tinted background.
-   Keep text contrast at WCAG AA or better where practical: at least
    4.5:1 for normal text and 3:1 for large text and meaningful UI
    graphics.
-   Avoid using low-contrast grey for essential text. `textTertiary` is
    only for non-essential metadata or disabled content.
-   Support dark theme only as a deliberate, separately tested token
    set; do not auto-invert the light palette.

------------------------------------------------------------------------

## Typography

### Typeface

Use **Roboto** as the baseline Android typeface to match native platform
expectations. If the product adopts a bundled brand font later, replace
it centrally rather than styling screens independently.

### Type scale

  ---------------------------------------------------------------------------
  Token                  Size / line height Weight           Usage
  ------------------- --------------------- ---------------- ----------------
  `type.display`                 30 / 36 sp Bold (700)       Rare, focused
                                                             hero heading

  `type.headline`                26 / 32 sp Bold (700)       Main page title
                                                             where space
                                                             allows

  `type.titleLarge`              20 / 26 sp SemiBold (600)   Primary card
                                                             title or hero
                                                             title

  `type.title`                   16 / 22 sp SemiBold (600)   Row title,
                                                             section title

  `type.body`                    14 / 20 sp Regular (400)    Main body and
                                                             descriptive
                                                             content

  `type.bodySmall`               12 / 16 sp Regular (400)    Helper text and
                                                             secondary
                                                             information

  `type.label`                   13 / 18 sp Medium (500)     Buttons, tabs,
                                                             selected options

  `type.caption`                 11 / 14 sp Medium (500)     Compact metadata
                                                             only
  ---------------------------------------------------------------------------

### Typography rules

-   Use a clear two-level hierarchy within cards: title first, secondary
    detail below.
-   Use sentence case. Avoid all-caps labels except short technical
    identifiers where necessary.
-   Prefer font weight and spacing over extra colors to create
    hierarchy.
-   Do not shrink text to fit. Allow long labels to wrap or use a clear
    truncation rule.
-   Support Android font scaling; test layouts at 1.0×, 1.3×, and 2.0×.
-   Use tabular numerals for counters, durations, byte sizes,
    timestamps, and other values users compare.

------------------------------------------------------------------------

## Layout and spacing

### Grid and screen insets

-   Use a **4 dp base spacing unit**.
-   Standard horizontal screen padding: **20 dp** on compact phones; use
    24 dp on wider phones when appropriate.
-   Content width should adapt to available space. Avoid stretching
    cards edge-to-edge on tablets.
-   Respect status bar, navigation bar, display cutout, and keyboard
    insets. Use edge-to-edge layouts only when system bars remain
    legible.
-   Main content scrolls vertically; keep primary actions reachable and
    do not place essential controls behind the keyboard.
-   Use a consistent alignment edge for screen titles, card content, and
    section headings.

### Spacing tokens

  Token          Value Usage
  ------------ ------- ------------------------------------
  `space.0`       0 dp No gap
  `space.1`       4 dp Icon-to-label micro-gap
  `space.2`       8 dp Tight internal gap
  `space.3`      12 dp Compact component spacing
  `space.4`      16 dp Standard internal padding
  `space.5`      20 dp Screen horizontal padding
  `space.6`      24 dp Section/card separation
  `space.8`      32 dp Major section separation
  `space.10`     40 dp Large hero spacing
  `space.12`     48 dp Focused empty/verification layouts

### Component sizing

-   Standard list row: **64--72 dp** minimum height depending on
    content.
-   Compact setting row: **56 dp** minimum height.
-   Primary button: **52--56 dp** height.
-   Text input: **52--56 dp** minimum height.
-   Icon-only button: **48 × 48 dp** touch target even if the glyph is
    smaller.
-   Checkbox, radio, and switch controls must retain comfortable touch
    targets.
-   Maintain at least **8 dp** between separate touch targets; prefer
    more where space permits.
-   Bottom navigation: use the platform-appropriate Material 3 component
    and ensure labels remain readable.

------------------------------------------------------------------------

## Elevation and depth

The reference uses mostly flat white cards against a light grey canvas.
Keep depth subtle.

  -----------------------------------------------------------------------
  Token                   Rule                    Usage
  ----------------------- ----------------------- -----------------------
  `elevation.none`        0 dp                    Main background and
                                                  simple grouped content

  `elevation.card`        1 dp or subtle tonal    Standard cards where
                          separation              background contrast
                                                  alone is insufficient

  `elevation.raised`      3 dp                    Menus, floating
                                                  controls, elevated
                                                  surfaces

  `elevation.modal`       8 dp                    Modal sheets/dialogs
                                                  where platform
                                                  conventions call for it
  -----------------------------------------------------------------------

-   Prefer a one-pixel-equivalent border or a slight surface contrast
    over heavy shadows.
-   Do not combine a strong border, strong shadow, and tinted fill on
    the same card.
-   Elevation communicates interaction/layering, not importance or
    severity.
-   Avoid neumorphism, glassmorphism, and large diffuse shadows.

------------------------------------------------------------------------

## Shapes

### Radius tokens

The reference uses rounded cards, pill-like option rows, and circular
status icons. Standardize those shapes as follows.

  ------------------------------------------------------------------------
  Token                                       Radius Usage
  --------------------- ---------------------------- ---------------------
  `radius.xs`                                   6 dp Small tags and
                                                     compact chips

  `radius.sm`                                  10 dp Inputs and compact
                                                     control containers

  `radius.md`                                  14 dp Standard cards and
                                                     grouped settings

  `radius.lg`                                  18 dp Large hero cards and
                                                     prominent feature
                                                     cards

  `radius.xl`                                  24 dp Large sheets or
                                                     focused hero
                                                     containers

  `radius.pill`                               999 dp Status badges,
                                                     segmented selection,
                                                     pill controls

  `radius.circle`                                50% Circular icon
                                                     containers and
                                                     progress indicators
  ------------------------------------------------------------------------

### Shape rules

-   Use one radius token consistently for the same component type.
-   Do not give each card a different radius for decoration.
-   Keep list rows square-edged within a grouped parent unless the
    reference specifically calls for individually selectable pill rows.
-   Toggles, check indicators, and circular progress marks follow their
    native component shape.
-   Avoid mixing sharp-cornered cards with highly rounded cards on the
    same screen without a functional reason.

------------------------------------------------------------------------

## Iconography

-   Use a single consistent outline icon family, preferably Material
    Symbols or the existing app icon set.
-   Default icon size: **20--24 dp**; large status/hero icon: **40--56
    dp**.
-   Standard leading icons use `color.textSecondary`; active icons may
    use `color.primary`; semantic states use success, warning, or danger
    tokens.
-   Keep stroke weight and optical size consistent.
-   Use icons that are recognizable without relying on color alone.
-   Every icon-only control requires a meaningful accessibility label.
-   Do not use emoji as interface icons.
-   Use a shield only where it genuinely communicates protection or a
    security feature; avoid repeating shield imagery in every card.

------------------------------------------------------------------------

## Reusable components

Every component below must be implemented once and reused. Component
APIs should accept state and content; screens should not create local
one-off styling variants without updating this document.

### 1. `ScreenScaffold`

**Purpose:** Standard page structure.

-   Background: `color.background`.
-   Horizontal content padding: `space.5`.
-   Standard vertical section gap: `space.6`.
-   Supports top app bar, scrollable content, optional bottom
    navigation, and system insets.
-   Screen title aligns to the same left edge as body content.
-   Never hardcode status-bar time or system icons into application UI.

**States:** default, loading, content, empty, error.

### 2. `TopAppBar`

-   Height: platform-appropriate Material 3 top app bar.
-   Title: `type.title`, `color.textPrimary`.
-   Leading back button: 48 dp touch target.
-   Trailing actions: icon buttons with accessibility labels.
-   Use a close (`X`) action only when it clearly dismisses a temporary
    flow or sheet; use back navigation for normal hierarchy.

### 3. `StatusHero`

**Reference source:** Full-protection overview screen.

-   Vertically centered icon inside a circular outline or quiet surface.
-   Hero icon: 44--56 dp.
-   Circle diameter: approximately 112--128 dp for a large hero; scale
    down on compact screens.
-   Title: `type.titleLarge`.
-   Description: `type.body`, secondary color, maximum readable line
    length.
-   Status ring: green only for a verified positive state; use amber/red
    when the state is caution/high-risk.
-   Avoid exaggerated animation. If animated, use a short, subtle
    transition and respect reduced-motion settings.

### 4. `FeatureStatusRow`

**Reference source:** Secure VPN, Antivirus, and ID Monitoring rows.

-   Minimum height: 72 dp for a two-line row.
-   Horizontal padding: 16 dp.
-   Leading icon: 24 dp, in a 40 dp visual area.
-   Title: `type.title` or `type.body` with medium weight.
-   Description: `type.bodySmall`, `color.textSecondary`.
-   Trailing area: status badge, switch, or chevron---never multiple
    competing actions.
-   Optional divider: `color.border`.
-   Whole row is clickable only when it navigates; use a separate switch
    if the toggle itself is the action.

**Variants:** - `navigable`: chevron, whole row opens detail. -
`toggle`: switch and explicit on/off state. - `status`: badge with
label, no misleading interactivity. - `evidence`: severity label plus
count or summary.

### 5. `StatusBadge`

-   Height: approximately 28 dp.
-   Horizontal padding: 10 dp.
-   Shape: `radius.pill`.
-   Text: `type.bodySmall` or `type.label`, medium weight.
-   Fill: semantic container token; foreground: matching semantic token.
-   Use concise labels such as `Enabled`, `Verified`, `Review`,
    `High risk`, `Unavailable`.
-   Never display `Safe` if a scan has not completed.

### 6. `SurfaceCard`

-   Fill: `color.surface`.
-   Radius: `radius.md` (14 dp).
-   Border: optional 1 dp `color.border`; use only where needed.
-   Elevation: `elevation.card` at most.
-   Padding: 16 dp standard; 20 dp for hero or subscription content.
-   Internal spacing: 12--16 dp.
-   Cards group related content. Avoid putting a card inside another
    card unless the nested content is a distinct interactive surface.

### 7. `PrimaryButton`

-   Height: 52--56 dp.
-   Fill: `color.primary`; label/icon: `color.onPrimary`.
-   Radius: `radius.md` (14 dp) unless native Material 3 defaults are
    retained consistently.
-   Label: `type.label`.
-   Full-width for primary form/scan actions when that is the clear next
    step.
-   One primary action per screen or visual region.
-   Disabled state must be visibly distinct and have an understandable
    reason where relevant.
-   Loading state shows progress and prevents duplicate submission.

### 8. `SecondaryButton` and `TextButton`

-   Secondary button: surface or subtle container with a border when
    needed.
-   Text button: transparent background, primary-colored label.
-   Do not style multiple buttons as equally primary.
-   Destructive actions use semantic danger styling and should require
    confirmation when consequences are significant.

### 9. `SearchField`

**Reference source:** Virtual Regions search.

-   Height: 52--56 dp.
-   Fill: `color.surfaceSubtle`.
-   Radius: `radius.sm` or `radius.md`.
-   Leading search icon: 20 dp.
-   Placeholder: `type.body`, `color.textSecondary`.
-   Clear action appears only when text exists.
-   Provide keyboard action and clear focus behavior.
-   Search should preserve user-entered text when returning from a
    result screen, unless the user explicitly clears it.

### 10. `SelectableOptionRow`

**Reference source:** Automatic location and region choices.

-   Minimum height: 52--60 dp.
-   Standard horizontal padding: 12--16 dp.
-   Unselected fill: `color.surface` or `color.surfaceSubtle`.
-   Selected fill: `color.primaryContainer`; selected indicator uses
    `color.primary` or success only if it represents verified status.
-   Label: `type.body` with medium weight.
-   Optional leading icon/avatar; trailing check/radio/favorite icon.
-   Selected state must be represented semantically for accessibility.
-   Use radio semantics for single selection and checkbox semantics for
    multiple selection.

### 11. `SettingsGroup` and `SettingRow`

-   Group background: `color.surface`.
-   Radius: `radius.md`.
-   Rows share consistent vertical padding and left alignment.
-   Use 1 dp dividers between related rows only when they improve
    scanning.
-   Toggle rows include a title and optional helper text.
-   Choice rows show the current value or selection.
-   Destructive rows are visually separated from ordinary preferences.
-   Do not place unrelated settings in one large undifferentiated card.

### 12. `SwitchControl`

-   Prefer the native Material 3 `Switch`.
-   Pair the control with a clear label and, where necessary, supporting
    text.
-   Use green only if the design system consistently maps green to
    enabled/active; otherwise preserve Material 3 state semantics.
-   The UI must update immediately to reflect pending state, then
    reconcile with the actual operation result.
-   If permission is required, explain the permission before opening
    system settings.
-   A switch must not imply protection is active until the underlying
    service confirms it.

### 13. `MetricCard`

**Reference source:** Data-transfer summary and threats-blocked summary.

-   Surface: `color.surface`.
-   Radius: `radius.md`.
-   Padding: 16 dp.
-   Label: `type.bodySmall`, secondary color.
-   Value: 24--28 sp, bold, primary text color.
-   Optional unit and trend are separate from the number.
-   Use consistent number formatting and units.
-   Do not invent metrics when data is unavailable; show `—` with an
    explanation instead.

### 14. `MiniBarChart`

-   Use one accent color for the highlighted data point and neutral bars
    for the rest.
-   Labels must remain legible at phone width; do not render every label
    if it becomes crowded.
-   Include a text summary or accessible chart description.
-   Distinguish zero, missing, and not-yet-loaded values.
-   For forensics metrics, provide a time range and data source so the
    chart is interpretable.

### 15. `SectionHeader`

-   Title: `type.title`.
-   Optional trailing action: text or icon button.
-   Gap below header: 12 dp.
-   Keep headings short and consistent.
-   Avoid introducing a new colored banner for every section.

### 16. `EmptyState`

-   Simple outline icon or restrained illustration.
-   Title: `type.title`.
-   Description: `type.body`, secondary color.
-   Optional single action.
-   Example: `No alerts yet` with a brief explanation.
-   Do not imply that an empty list means the device is safe or has been
    fully scanned.

### 17. `SegmentedControl`

**Reference source:** Profile tabs.

-   Use Material 3 segmented buttons or a single reusable custom
    component.
-   Selected segment: `color.primary` with `color.onPrimary` text where
    a filled pill is used.
-   Unselected segment: neutral surface and secondary text.
-   Height: approximately 40--44 dp.
-   Labels must remain readable; avoid shrinking or clipping them.
-   Provide selected state to accessibility services.

### 18. `PlanOrSummaryCard`

**Reference source:** Subscription card.

For Sentinel Forensics, use this pattern for an investigation summary,
local protection summary, or enabled feature bundle---not to introduce a
subscription model unless the product actually has one.

-   Dark or high-contrast feature artwork is optional, not a default.
-   Title and status appear above a short list of included features.
-   Each benefit uses a small semantic icon and a concise label.
-   Keep artwork secondary to information.
-   Do not imply that a capability is included or active unless the
    application supports it.

### 19. `CodeEntryField`

**Reference source:** Enter-code screen.

-   Use a focused page or bottom sheet with a clear title and concise
    instructions.
-   For a six-digit code, use six visual cells backed by a single
    accessible input where feasible.
-   Support paste, autofill where appropriate, and keyboard navigation.
-   Error text appears directly below the input and explains how to
    recover.
-   Do not clear valid input on a transient error unless required.
-   Provide resend timing/status if a resend action exists.
-   Never show a real authentication code in logs, analytics, or
    screenshots.

### 20. `EvidenceFindingCard` --- Sentinel-specific extension

**Purpose:** Present an understandable scan or forensic finding.

-   Header: finding name plus severity badge.
-   Summary: one or two sentences explaining what was detected.
-   Evidence list: concrete indicators such as suspicious URL features,
    file metadata mismatch, or model output.
-   Metadata: scan time, engine/version, file hash where relevant, and
    scan scope.
-   Actions: `View details`, `Save to case`, `Export report` when
    supported.
-   Distinguish **observed evidence**, **heuristic inference**, and
    **model prediction**.
-   A probability score is not proof. Explain uncertainty and
    limitations.

### 21. `BottomNavigation`

The reference uses a simple three-item bottom bar. For Sentinel
Forensics, choose the destinations based on product information
architecture; recommended starting point:

-   **Home** --- overview and recent status.
-   **Scan** --- start or continue a scan.
-   **Alerts** --- findings requiring attention.
-   **Cases** --- saved investigations and evidence.
-   **Settings** --- permissions, local intelligence, privacy, and app
    preferences.

If five destinations create crowding on compact screens, use four
primary destinations and place the remaining destination under a clear
secondary navigation pattern. Do not compress labels or rely on icons
alone. Keep the selected state visible and consistent.

------------------------------------------------------------------------

## Sentinel Forensics screen patterns

These are product-specific extensions that reuse the components above;
they are not additional screens proven by the reference image.

### Home / overview

1.  Top app bar and concise greeting or product title.
2.  One `StatusHero` or summary panel showing the actual local
    protection/engine state.
3.  Primary action: `Start a scan`.
4.  A small number of `FeatureStatusRow` items for core scan tools.
5.  Recent `EvidenceFindingCard` summaries or an honest empty state.
6.  Avoid a wall of equally weighted tool cards. Prioritize the most
    frequent tasks.

### Scan selection

-   Use a clear page title and short description.
-   Group scan types into understandable categories: URL/message,
    image/video, file, and network where supported.
-   Each option uses a consistent icon, title, one-line explanation, and
    clear tap affordance.
-   Do not display an `Active` badge for a feature that is merely
    installed.
-   If a feature needs a file, permission, or network, disclose that
    requirement before the user begins.

### Scan progress

-   Show the current stage, not a fabricated percentage.
-   Use determinate progress only when the implementation can measure it
    meaningfully.
-   Show cancel/stop only when cancellation is safe and implemented.
-   Preserve the selected input and report recoverable failures.
-   If offline intelligence is stale or unavailable, say so explicitly
    rather than treating missing checks as a clean result.

### Findings / alerts

-   Lead with severity and a plain-language summary.
-   Present actionable evidence before technical detail.
-   Include `Why flagged`, `What was checked`, and
    `What could not be checked` when relevant.
-   Provide safe next steps without guaranteeing an outcome.
-   A low-risk or no-match result must not be phrased as a guarantee of
    safety.

### Cases and evidence

-   Reuse the same `SurfaceCard`, `SectionHeader`,
    `SelectableOptionRow`, and metadata typography.
-   Keep evidence identifiers, timestamps, hashes, and source paths in a
    stable, copyable format.
-   Make export actions explicit about file format and included data.
-   Do not silently modify original evidence. Record derived artifacts
    separately from source files.
-   Use a confirmation step before deleting a case or removing evidence.

### Settings and permissions

-   Group settings by purpose: Scanning, Privacy and storage,
    Notifications, Appearance, and About.
-   Explain why a permission is needed and what data the app can access.
-   Use Android system permission dialogs; do not imitate them with
    custom UI.
-   Show permission state and a route to system settings if the
    permission has been denied.
-   Do not claim unrestricted scanning of other apps' private data.

------------------------------------------------------------------------

## Interaction and motion

-   Standard tap feedback should be immediate and subtle.
-   Use short transitions, generally around **150--250 ms**, for state
    changes and navigation where appropriate.
-   Prefer fade/scale or small horizontal transitions over large
    theatrical motion.
-   Use a progress indicator for work that takes noticeable time.
-   Never animate a status from unsafe to safe without a real scan
    result.
-   Respect Android animator-duration and reduced-motion preferences
    where available.
-   Keep touch feedback, loading, success, warning, and failure behavior
    consistent across the app.
-   Confirm destructive actions; do not add confirmation dialogs to
    harmless navigation.

------------------------------------------------------------------------

## States and semantics

Every interactive component should define, where applicable:

-   `default`
-   `pressed`
-   `focused`
-   `selected`
-   `disabled`
-   `loading`
-   `success`
-   `warning`
-   `error`
-   `unavailable`

For scan features, also define:

-   `not_scanned`
-   `scanning`
-   `completed_no_match`
-   `potential_risk`
-   `high_risk`
-   `partial_result`
-   `cancelled`
-   `failed`
-   `offline_limited`
-   `permission_required`

Do not collapse these into one generic green/red state. Each state has a
different meaning and next action.

------------------------------------------------------------------------

## Accessibility

-   Meet WCAG AA contrast targets wherever possible.
-   Provide at least 48 × 48 dp touch targets for interactive controls.
-   Supply semantic labels for icon-only buttons and meaningful state
    descriptions for switches, badges, charts, and selection controls.
-   Do not communicate severity, selection, or completion through color
    alone.
-   Support font scaling and screen readers.
-   Avoid truncating important evidence, file names, risk explanations,
    or permission guidance.
-   Preserve logical reading order and keyboard/D-pad navigation where
    applicable.
-   Announce scan progress and completion without flooding accessibility
    announcements.
-   Ensure selected controls expose selected/checked state.
-   Test both light and dark themes if dark mode is shipped.

------------------------------------------------------------------------

## Responsive behavior

-   **Compact phones:** One column, 20 dp horizontal padding, stacked
    content, no side-by-side cards that squeeze text.
-   **Larger phones:** Preserve content max-width and whitespace; do not
    inflate every control.
-   **Tablets/foldables:** Use a centered content column or adaptive
    two-pane layout for list/detail flows. Keep tap targets and
    typography stable.
-   **Landscape:** Scrollable content must remain usable with the
    keyboard and system bars visible.
-   **Short screens:** Reduce decorative hero spacing before reducing
    text size or touch-target dimensions.

------------------------------------------------------------------------

## Implementation guidance --- Jetpack Compose

Use a central theme and token definitions rather than literal colors and
dimensions repeated throughout composables.

Recommended structure (adapt names to the existing repository; do not
create duplicate modules without first auditing its architecture):

``` text
ui/
  theme/
    Color.kt
    Type.kt
    Shape.kt
    Spacing.kt
    Theme.kt
  components/
    ScreenScaffold.kt
    StatusHero.kt
    FeatureStatusRow.kt
    StatusBadge.kt
    SurfaceCard.kt
    SearchField.kt
    SelectableOptionRow.kt
    SettingRow.kt
    MetricCard.kt
    EmptyState.kt
    EvidenceFindingCard.kt
  screens/
    home/
    scan/
    alerts/
    cases/
    settings/
```

Implementation rules:

1.  Define colors, typography, shapes, and spacing centrally.
2.  Prefer Material 3 components where they meet the design; wrap them
    only when a consistent product-specific API is needed.
3.  Use state-driven composables. UI status must reflect the actual
    state from the view model or domain layer.
4.  Keep detection and evidence logic out of composables.
5.  Use previews for default, loading, empty, warning, error, and
    large-font states.
6.  Reuse components through parameters such as `title`, `description`,
    `leadingIcon`, `status`, `enabled`, and `onClick`.
7.  Avoid styling by screen index or one-off conditional colors; use
    semantic tokens.
8.  Confirm existing dependencies and module boundaries before changing
    project structure.

Example token declaration (illustrative; align naming with the
repository's existing theme):

``` kotlin
object AppSpacing {
    val x1 = 4.dp
    val x2 = 8.dp
    val x3 = 12.dp
    val x4 = 16.dp
    val x5 = 20.dp
    val x6 = 24.dp
    val x8 = 32.dp
}

object AppShape {
    val small = RoundedCornerShape(10.dp)
    val card = RoundedCornerShape(14.dp)
    val large = RoundedCornerShape(18.dp)
    val pill = RoundedCornerShape(percent = 50)
}
```

The example is a starting point, not a mandate to replace existing
project tokens without review.

------------------------------------------------------------------------

## Do and don't

### Do

-   Use white cards against a cool-neutral background.
-   Keep spacing and card radii consistent.
-   Use blue for primary action/selection and semantic colors for actual
    status.
-   Make the current state and next action easy to scan.
-   Show supporting evidence and limitations for security findings.
-   Reuse components and test their states.
-   Follow Android navigation and permission conventions.
-   Label estimated or partial results honestly.

### Don't

-   Don't copy the reference's VPN-specific branding or text into
    Sentinel Forensics.
-   Don't add gradients, excessive shadows, or decorative glows.
-   Don't use green to mean "not scanned" or "no data."
-   Don't display fake live metrics, invented scan percentages, or
    unverified "protection active" states.
-   Don't rely on color alone for status.
-   Don't build a new bespoke card for every screen.
-   Don't imply the app can inspect every installed app's private files
    or intercept every link system-wide.
-   Don't treat a model score as definitive proof of fraud, deepfake
    content, or malware.

------------------------------------------------------------------------

## Design QA checklist

Before a screen is considered complete, verify:

-   [ ] All colors use named semantic tokens.
-   [ ] All spacing uses the spacing scale.
-   [ ] Card and control radii match the shared shape scale.
-   [ ] Typography uses the defined type scale.
-   [ ] Interactive targets are at least 48 × 48 dp.
-   [ ] Loading, empty, success, warning, error, and unavailable states
    are designed where applicable.
-   [ ] Security states have text labels and are not color-only.
-   [ ] Screen reader labels and selected/checked states are correct.
-   [ ] Large text does not clip or hide actions.
-   [ ] Insets and keyboard behavior are correct.
-   [ ] UI status reflects real implementation state.
-   [ ] No unsupported security promise is shown.
-   [ ] Components are reused instead of duplicated.

------------------------------------------------------------------------

## References

These external sources informed the structure and implementation
guidance; the visual values above are derived from the supplied
screenshot and design judgment.

-   [Google Labs --- DESIGN.md format
    specification](https://github.com/google-labs-code/design.md/blob/main/docs/spec.md)
    --- document structure, design-token organization, and component
    guidance.
-   [Android Developers --- Material 3 in Jetpack
    Compose](https://developer.android.com/develop/ui/compose/designsystems/material3)
    --- color, typography, shape, and theming.
-   [Android Developers --- Material Design for
    Android](https://developer.android.com/develop/ui/views/theming/look-and-feel)
    --- platform design and component guidance.
-   [Apple Human Interface
    Guidelines](https://developer.apple.com/design/human-interface-guidelines)
    --- cross-platform reference for hierarchy, consistency, layout, and
    accessibility principles.

------------------------------------------------------------------------

## Change log

-   **v0.1 --- Initial reference-derived specification:** Documented the
    seven visible screen patterns, estimated initial tokens, defined
    reusable components and states, and added Sentinel
    Forensics-specific finding/evidence patterns.
