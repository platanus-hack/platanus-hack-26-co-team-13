---
name: Provenance Firewall
description: Chain-of-custody evidence for deterministic source authorization.
colors:
  mineral-ground: "#f4f1e7"
  ledger-paper: "#fffdf7"
  carbon-ink: "#202c28"
  faded-ink: "#53615b"
  ledger-line: "#c9cec5"
  custody-line: "#87958e"
  custody-blue: "#1f56c5"
  custody-blue-pale: "#e4ebfb"
  evidence-yellow: "#f2b735"
  failure-red: "#c13d30"
  failure-red-pale: "#f9e3dc"
  verified-green: "#26715b"
  verified-green-pale: "#dfeee6"
typography:
  display:
    fontFamily: "Unbounded, sans-serif"
    fontSize: "clamp(3.2rem, 5.2vw, 5.3rem)"
    fontWeight: 650
    lineHeight: 0.96
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Unbounded, sans-serif"
    fontSize: "clamp(2.35rem, 4.5vw, 4.8rem)"
    fontWeight: 600
    lineHeight: 1.05
    letterSpacing: "-0.03em"
  title:
    fontFamily: "Unbounded, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "18px"
    fontWeight: 400
    lineHeight: 1.65
  label:
    fontFamily: "Unbounded, sans-serif"
    fontSize: "10px"
    fontWeight: 750
    lineHeight: 1
    letterSpacing: "0.07em"
  mono:
    fontFamily: "ui-monospace, monospace"
    fontSize: "11px"
    fontWeight: 400
    lineHeight: 1.4
rounded:
  square: "0"
  scrollbar: "999px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "20px"
  xl: "24px"
  xxl: "30px"
components:
  button-primary:
    backgroundColor: "{colors.custody-blue}"
    textColor: "#ffffff"
    typography: "{typography.body}"
    rounded: "{rounded.square}"
    padding: "0 18px"
    height: "48px"
  button-primary-hover:
    backgroundColor: "#1747a6"
    textColor: "#ffffff"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.carbon-ink}"
    rounded: "{rounded.square}"
    padding: "0 18px"
    height: "40px"
  tab-active:
    backgroundColor: "{colors.carbon-ink}"
    textColor: "{colors.ledger-paper}"
    rounded: "{rounded.square}"
    padding: "14px 20px"
  evidence-sheet:
    backgroundColor: "{colors.ledger-paper}"
    textColor: "{colors.carbon-ink}"
    rounded: "{rounded.square}"
    padding: "34px"
  status-stamp:
    backgroundColor: "transparent"
    textColor: "{colors.failure-red}"
    typography: "{typography.label}"
    rounded: "{rounded.square}"
    padding: "9px 12px"
---

# Design System: Provenance Firewall

## Overview

**Creative North Star: "The Chain-of-Custody Dossier"**

Provenance Firewall presents security as physical, reviewable evidence. Mineral paper, custody-blue annotations, evidence-yellow bands, failure-red stamps, perforations, signed ledger sheets, and slight document rotations make source authority visible without falling into either cyberpunk theater or a generic SaaS security dashboard.

The system alternates between persuasive evidence artifacts and a dense operating surface. The first mode uses oversized numbers, split statements, and documents that appear handled and stamped; the second uses strict tables, inspectors, tabs, and explicit state labels. Square construction, dark rules, and restrained shadows keep both modes part of the same evidentiary world.

The primary implementation uses no shipping raster imagery. Its seal and paper details are CSS, and its interface symbols are inline SVG icons. Any future shipping raster must carry recorded provenance; an unreviewed or undocumented asset is unfinished.

**Key Characteristics:**

- Mineral-paper light surfaces with dark, ledger-like rules.
- Custody blue for traced authority and interactive emphasis.
- Evidence yellow for proof and attention, failure red for blocked or unsafe outcomes, and verified green for successful controls.
- Square forms, stamps, perforations, signed sheets, and tabular evidence instead of rounded dashboard cards.
- Unbounded for declarative statements and labels; Public Sans for explanatory and operating text.
- A deliberate shift from 50,000 exposed records to zero, then from explanation into a live control plane.

## Colors

The palette reads like a marked case file: warm paper and green-black ink carry the document, while saturated custody colors encode trace, evidence, failure, and verification.

### Primary

- **Custody Blue:** The authoritative interaction and trace color. Use it for primary actions, linked arguments, active source trails, and the emphasized clause in the opening statement.
- **Custody Blue Pale:** The selected-row and traced-argument wash. It highlights provenance without turning an entire surface blue.

### Secondary

- **Evidence Yellow:** A high-attention proof color for the four-part evidence band, text selection, dark-section links, and the final inverted action.

### Tertiary

- **Failure Red:** Marks untrusted sources, blocks, vulnerable outcomes, escalation stamps, and offline indicators. It is a verdict color, not general decoration.
- **Failure Red Pale:** Supports failure context when a full red field would overpower the evidence.
- **Verified Green:** Marks protected zero outcomes, valid signatures, online state, passed identity checks, and successful authorization controls.
- **Verified Green Pale:** Gives approved decision documents a quiet verified field while preserving dark text contrast.

### Neutral

- **Mineral Ground:** The warm page canvas and sticky-header field.
- **Ledger Paper:** The near-white stock used for custody labels, evidence sheets, consoles, and controls.
- **Carbon Ink:** The green-black text, rule, active-tab, dark evidence-section, and toast color.
- **Faded Ink:** Secondary explanations, metadata, and inactive labels.
- **Ledger Line:** Routine dividers and table rules.
- **Custody Line:** Stronger boundaries, control outlines, and perforation marks.

### Named Rules

**The Verdict Color Rule.** Red and green communicate explicit security outcomes; pair them with labels, icons, or numbers so color never carries the verdict alone.

**The Evidence Yellow Rule.** Yellow marks proof or a deliberate call to inspect it. Do not use it as a generic cheerful accent.

**The Paper Majority Rule.** Mineral ground and ledger paper remain the visual majority; saturated colors work because they are bounded and evidentiary.

## Typography

**Display Font:** Unbounded (with sans-serif fallback)
**Body Font:** Public Sans (with sans-serif fallback)
**Label/Mono Font:** Unbounded for institutional labels; system UI monospace for signatures and identifiers

**Character:** Unbounded gives verdicts, totals, and custody labels a wide, engineered authority. Public Sans keeps explanations and dense operating controls direct and legible; monospace appears only where data should feel inspectable rather than branded.

### Hierarchy

- **Display** (650, fluid hero scale, 0.96 line-height): Opening statements and oversized result numbers. It is tightly tracked and may use tabular numerals for comparisons.
- **Headline** (600, fluid section scale, 1.05 line-height): Section theses and closing statements, balanced across short lines.
- **Title** (600, 16px, 1.2 line-height): Control-plane headings, inspector titles, and compact artifact titles.
- **Body** (400, 18px, 1.65 line-height): Explanations and evidence narrative, generally constrained to about 62-65 characters per line.
- **Label** (750, 8-13px, 0.05-0.08em tracking, uppercase): Case metadata, table headers, statuses, and document annotations.
- **Mono** (400, 11-13px): Tool arguments, signatures, escalation identifiers, and immutable evidence references.

### Named Rules

**The Institutional Label Rule.** Use uppercase Unbounded sparingly for metadata and state, never for paragraphs.

**The Number Is Evidence Rule.** Consequential totals are large, tightly set, and tabular; 50,000 and zero must scan before their explanation.

## Layout

The page uses broad, full-width bands with content bounded by fluid horizontal padding. The opening viewport is a two-column split between a declarative statement and an oversized custody label; below it, the proof bar spans four equal cells. Explanatory sections use asymmetric two-column grids, while the mechanism becomes a three-document trace connected by arrows.

The control plane is a bounded 1500px operating surface. Provenance uses a 310px scenario rail beside flexible output; memory and ledger views use a 1.45-to-0.55 table/inspector split. Dense rows preserve explicit columns and allow horizontal scrolling instead of collapsing evidence into ambiguous cards.

Spacing is generous between narrative sections and compact inside operational tables. Repeated component spacing follows an 8-30px working rhythm, while section padding expands to roughly 80-130px. At 1160px, document and inspector grids stack. At 760px, navigation becomes a square menu, the hero and evidence comparisons stack, the proof band becomes two columns, and data tables retain minimum widths inside horizontal scrollers.

**The Artifact-to-Console Rule.** Persuasive sections may rotate and breathe; operating sections align to strict columns and square borders.

## Elevation & Depth

The system is flat by default. Depth is structural and reserved for loose evidence artifacts: the custody hero, trace documents, ledger sheet, and toast receive broad, low-opacity shadows. Consoles, tabs, tables, and controls rely on paper tones and one-pixel rules rather than floating cards. Slight rotations imply handled documents, then disappear at narrower breakpoints where stability matters more than theatricality.

### Shadow Vocabulary

- **Custody Lift** (`0 26px 70px rgba(44, 52, 47, .15)`): The oversized first-viewport evidence label.
- **Document Lift** (`0 18px 45px rgba(44, 52, 47, .09)`): Source, argument, and decision documents in the trace.
- **Ledger Lift** (`0 28px 60px rgba(0, 0, 0, .22)`): The verified sheet against the dark evidence field.
- **Toast Lift** (`0 16px 40px rgba(22, 29, 26, .24)`): The fixed transient status message.

### Named Rules

**The Loose-Paper Rule.** Shadows and rotation belong to evidence that reads as a handled sheet, never to routine dashboard containers.

## Shapes

Square geometry is the default. Buttons, tabs, cards, tables, stamps, seals, inspectors, and state indicators use hard corners and one-pixel rules. Nested borders, dotted perforations, underlines, and ruled rows provide detail without ornamental radius. The only fully rounded form is the browser scrollbar thumb, a platform affordance rather than a component motif.

Stamps use two-pixel verdict borders and slight rotation. Evidence sheets may rotate by roughly one degree on wide screens, while their interior grids remain orthogonal. Icon containers remain square and compact.

**The No Soft Card Rule.** Do not introduce rounded, floating SaaS cards; divide information with paper fields, rules, columns, and ledger rows.

## Components

### Buttons

- **Shape:** Square, compact, and weighty, with no border radius.
- **Primary:** Custody-blue field with white text, a 48px minimum height, 18px horizontal padding, and an inline 17px icon.
- **Hover / Focus:** Hover deepens the blue. Keyboard focus uses a visible 3px custody-blue outline with a 3px offset; disabled running states reduce opacity and use a wait cursor.
- **Secondary:** Transparent, 40px high, and enclosed by a custody-line border; hover fills with ledger paper.
- **Text action:** Borderless and underlined in evidence yellow on dark fields, reserved for inspecting supporting evidence.

### Chips

- **Style:** Connection state is a square ledger-paper label with a custody-line border, uppercase Unbounded text, and a separate square status indicator.
- **State:** The indicator is failure red for preview/offline and verified green for live. State remains written in text.

### Cards / Containers

- **Corner Style:** Hard square corners throughout.
- **Background:** Ledger paper for evidence artifacts and consoles; verified-green pale for a successful decision document; warm mineral variants for inspector rails.
- **Shadow Strategy:** Only loose paper artifacts receive lift; consoles and table containers stay flat.
- **Border:** One-pixel carbon or custody rules; stamps use two-pixel verdict borders.
- **Internal Padding:** 24-34px for evidence sheets, 28-30px for control rails, and 13-20px for rows.

### Navigation

- **Style:** A 72px sticky mineral-paper header with a square nested-rule seal, compact text links, and a carbon action button. At 760px it becomes a 64px header with a square menu control and a full-width ruled dropdown.
- **States:** Text links underline on hover; keyboard focus follows the global 3px custody-blue outline.

### Custody Label

The signature first-viewport component is a large ledger-paper case label with an inset rule, dotted perforation, fixed 50,000-to-zero comparison, source route, and rotated failure-red stamp. Protected execution animates the stamp once; reduced-motion preferences collapse that motion to effectively instant.

### Evidence Tables

Tables use uppercase Unbounded headers, compact Public Sans rows, tabular or monospace evidence values, and one-pixel horizontal rules. Selected memory rows use custody-blue pale, argument values use custody blue, and decisions retain written labels alongside verdict colors. On small screens, tables scroll horizontally rather than silently dropping columns.

## Do's and Don'ts

### Do:

- **Do** make source, authority, requirement, decision, and signature visible as a chain of evidence.
- **Do** use square paper artifacts, strict rules, stamps, perforations, and ledger rows to organize proof.
- **Do** reserve custody blue for action and trace, evidence yellow for proof, and verdict colors for explicit outcomes.
- **Do** keep the 50,000-to-zero result visually dominant and pair every result color with text or iconography.
- **Do** preserve strict operating columns and horizontal scrolling when evidence cannot collapse safely.
- **Do** attach provenance to every raster that is approved for shipping; prefer CSS or inline SVG when an asset does not need to be rasterized.

### Don't:

- **Don't** turn the interface into a generic rounded-card SaaS security dashboard.
- **Don't** use dark cyberpunk surfaces, neon glows, glass cards, or decorative threat-map imagery.
- **Don't** add shadows or rotation to ordinary controls, tabs, tables, or console containers.
- **Don't** use red and green without a written verdict, state label, number, or icon.
- **Don't** fabricate customer imagery, production evidence, testimonials, or security claims.
- **Don't** ship an unreviewed, undocumented, or provenance-free raster asset.
