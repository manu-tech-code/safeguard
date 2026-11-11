import AppKit
import CoreText
import SwiftUI

// MARK: - Looks
//
// One set of components, seven looks. Each look is a `Skin`: a palette, a type system, shape
// rules and a few layout choices. Components read `Theme.skin` as they draw; switching look
// rebuilds the window (see RootView).
//
//   A Graphite   quiet dark dashboard, lime accent, Geist
//   B Field Ops  terminal instrument panel, amber, JetBrains Mono
//   C Dot Matrix black with dotted numerals, one red alert, Doto + Space Grotesk
//   D Bento      soft charcoal tiles, coral hero, Bricolage Grotesque + Inter
//   E Swiss      typographic, thick rules, no panels, Inter Tight
//   F Hardware   embossed panels, keycap buttons, sage LCD, IBM Plex
//   G Neo-Brutal light paper, black outlines, hard shadows, bright fills, Space Grotesk

enum Look: String, CaseIterable, Identifiable {
    case graphite, fieldops, dotmatrix, bento, swiss, hardware, brutal
    var id: String { rawValue }

    var letter: String {
        switch self {
        case .graphite: "A"
        case .fieldops: "B"
        case .dotmatrix: "C"
        case .bento: "D"
        case .swiss: "E"
        case .hardware: "F"
        case .brutal: "G"
        }
    }

    var title: String {
        switch self {
        case .graphite: "Graphite"
        case .fieldops: "Field Ops"
        case .dotmatrix: "Dot Matrix"
        case .bento: "Bento"
        case .swiss: "Swiss"
        case .hardware: "Hardware"
        case .brutal: "Neo-Brutal"
        }
    }

    var blurb: String {
        switch self {
        case .graphite: "Calm dark dashboard, lime accent, ring gauge"
        case .fieldops: "Terminal panel, amber on black, monospaced"
        case .dotmatrix: "Black, dotted numerals, a single red alert"
        case .bento: "Soft tiles, big friendly numbers, coral accent"
        case .swiss: "Pure type and thick rules, no boxes"
        case .hardware: "Embossed panels, keycap buttons, LCD score"
        case .brutal: "Light paper, black outlines, hard shadows"
        }
    }

    var skin: Skin { Skin.make(self) }
}

enum Chrome { case rail, ops, sidebar, topbar }
enum PanelKind { case filled, ruled }
enum RowStyle { case slab, solid, dashed, dotted }
enum PillStyle { case tinted, outlined, sticker }
enum BadgeStyle { case chip, marker, plain, sticker }

enum FontFace {
    case bricolage, inter, jetbrains, geist, geistMono, doto, spaceGrotesk, spaceMono
    case interTight, plexSans, plexMono, systemSans, systemMono
}

struct Skin {
    var dark = true

    // Palette (0xRRGGBB)
    var bg: UInt32 = 0x0E0E0F
    var tile: UInt32 = 0x1A1A1C
    var inset: UInt32 = 0x232325
    var insetHover: UInt32 = 0x2B2B2E
    var well: UInt32 = 0x121213
    var line: UInt32 = 0x2C2C2F
    var rule: UInt32 = 0x2C2C2F          // rules between rows
    var edge: UInt32 = 0x3D3D41          // outlines of buttons and fields
    var text: UInt32 = 0xF2F1EF
    var text2: UInt32 = 0xB3B1AC
    var text3: UInt32 = 0x8A8883
    var dim: UInt32 = 0x4A4946
    var accent: UInt32 = 0xFF6B3D
    var accentHover: UInt32 = 0xFF7D54
    var accentInk: UInt32 = 0x160A05     // text on an accent fill
    var accentText: UInt32 = 0xFF6B3D    // accent used as text
    var red: UInt32 = 0xFF5A4E
    var amber: UInt32 = 0xFFB547
    var green: UInt32 = 0x6BD69A
    var blue: UInt32 = 0x7DB8FF
    var spark: UInt32 = 0x3A3936
    var onFill: UInt32 = 0x14110E        // ink on bright fills
    var warnFill: UInt32 = 0xFFB547      // bright fill for "something is off"
    var warnInk: UInt32 = 0x1F1404

    // Hero blocks: filled with the state colour, or plain with coloured text.
    var heroFilled = true
    var hero: [UInt32] = [0x9FE8B9, 0xFF6B3D, 0xFF4F45]       // secure, watch, danger
    var heroInk: [UInt32] = [0x07180D, 0x160A05, 0x1A0504]
    var heroSoft: [UInt32] = [0x1F4A2E, 0x3A1A0C, 0x420E0A]

    // Type
    var fontDisplay: FontFace = .bricolage
    var fontFigure: FontFace = .bricolage
    var fontUI: FontFace = .inter
    var fontMono: FontFace = .systemMono
    var displayScale: CGFloat = 1
    var figureScale: CGFloat = 1
    var uiScale: CGFloat = 1
    var displayShift: CGFloat = 0
    var figureWeight: CGFloat? = nil
    var capsLabels = false               // small labels in capitals
    var capsControls = false             // buttons, headings, nav in capitals
    var monoLabels = false               // small labels in the mono face
    var monoTags = false                 // pills and badges in the mono face
    var tracking: CGFloat = 1

    // Shape
    var radiusScale: CGFloat = 1
    var pillRadius: CGFloat = 999
    var roundRadius: CGFloat = 999
    var dotRadius: CGFloat = 999
    var barRadius: CGFloat = 999

    // Surfaces
    var panelKind: PanelKind = .filled
    var panelBorder: UInt32? = nil
    var panelBorderWidth: CGFloat = 1
    var panelShadow: CGFloat = 0
    var panelEmboss = false
    var ruleWidth: CGFloat = 1
    var tilePadMax: CGFloat = 999
    var fieldBorder: UInt32? = nil
    var fieldBorderWidth: CGFloat = 1
    var rows: RowStyle = .slab
    var pills: PillStyle = .tinted
    var badge: BadgeStyle = .chip
    var switchBlock = false

    // Layout
    var chrome: Chrome = .rail
    var minWidth: CGFloat = 980
    var gap: CGFloat = 12
    var outer: CGFloat = 0               // margin around nav and page
    var padLead: CGFloat = 8
    var padTrail: CGFloat = 32
    var padTop: CGFloat = 40
    var padBottom: CGFloat = 28

    static func make(_ look: Look) -> Skin {
        var s = Skin()
        switch look {
        case .bento:
            break

        case .graphite:
            s.bg = 0x0C0D0F; s.tile = 0x131417; s.inset = 0x17191C; s.insetHover = 0x1D2024; s.well = 0x101113
            s.line = 0x212328; s.rule = 0x1B1D21; s.edge = 0x2C2F35
            s.text = 0xECEDEF; s.text2 = 0xA7ABB3; s.text3 = 0x8B9099; s.dim = 0x4A4E56
            s.accent = 0xC8F560; s.accentHover = 0xD8FA85; s.accentInk = 0x0C0D0F; s.accentText = 0xC8F560
            s.red = 0xFF6A5C; s.amber = 0xF7B23B; s.green = 0xC8F560; s.blue = 0x7FA8E8; s.spark = 0x2A2D33
            s.onFill = 0x0C0D0F; s.warnFill = 0xF7B23B; s.warnInk = 0x0C0D0F
            s.heroFilled = false; s.hero = [0xC8F560, 0xF7B23B, 0xFF6A5C]
            s.fontDisplay = .geist; s.fontFigure = .geist; s.fontUI = .geist; s.fontMono = .geistMono
            s.displayShift = -100
            s.radiusScale = 0.55; s.pillRadius = 8; s.roundRadius = 8; s.dotRadius = 2; s.barRadius = 3
            s.panelBorder = 0x212328
            s.tilePadMax = 22
            s.fieldBorder = 0x2C2F35
            s.rows = .solid; s.badge = .marker
            s.chrome = .sidebar; s.minWidth = 1100; s.gap = 12
            s.padLead = 36; s.padTrail = 36; s.padTop = 38; s.padBottom = 28

        case .fieldops:
            s.bg = 0x0A0A09; s.tile = 0x0A0A09; s.inset = 0x14130E; s.insetHover = 0x1D1B12; s.well = 0x0F0E0A
            s.line = 0x2B2717; s.rule = 0x2B2717; s.edge = 0x4A4430
            s.text = 0xE9E3D2; s.text2 = 0xB5AD92; s.text3 = 0x9C947A; s.dim = 0x5F5942
            s.accent = 0xFFB000; s.accentHover = 0xFFC433; s.accentInk = 0x0A0A09; s.accentText = 0xFFB000
            s.red = 0xFF5A47; s.amber = 0xFFB000; s.green = 0x7FD37A; s.blue = 0x6FB1C8; s.spark = 0x3A3624
            s.onFill = 0xE9E3D2; s.warnFill = 0xFFB000; s.warnInk = 0x0A0A09
            s.heroFilled = false; s.hero = [0x7FD37A, 0xFFB000, 0xFF5A47]
            s.fontDisplay = .jetbrains; s.fontFigure = .jetbrains; s.fontUI = .jetbrains; s.fontMono = .jetbrains
            s.displayScale = 0.72; s.figureScale = 0.72; s.uiScale = 0.9
            s.capsLabels = true; s.capsControls = true; s.tracking = 1
            s.radiusScale = 0; s.pillRadius = 0; s.roundRadius = 0; s.dotRadius = 0; s.barRadius = 0
            s.panelBorder = 0x2B2717
            s.tilePadMax = 18
            s.fieldBorder = 0x4A4430
            s.rows = .dashed; s.pills = .outlined; s.badge = .marker; s.switchBlock = true
            s.chrome = .ops; s.minWidth = 1040
            s.padLead = 26; s.padTrail = 26; s.padTop = 20; s.padBottom = 20

        case .dotmatrix:
            s.bg = 0x000000; s.tile = 0x111111; s.inset = 0x1A1A1A; s.insetHover = 0x222222; s.well = 0x0A0A0A
            s.line = 0x333333; s.rule = 0x333333; s.edge = 0x444444
            s.text = 0xFFFFFF; s.text2 = 0xB4B4B4; s.text3 = 0xA0A0A0; s.dim = 0x555555
            s.accent = 0xFF3B30; s.accentHover = 0xFF6A60; s.accentInk = 0x000000; s.accentText = 0xFF3B30
            s.red = 0xFF3B30; s.amber = 0xFFB020; s.green = 0xC8C8C8; s.blue = 0x9DB7FF; s.spark = 0x262626
            s.onFill = 0x000000; s.warnFill = 0xFFB020; s.warnInk = 0x000000
            s.heroFilled = false; s.hero = [0xFFFFFF, 0xFF3B30, 0xFF3B30]
            s.fontDisplay = .spaceGrotesk; s.fontFigure = .doto; s.fontUI = .spaceGrotesk; s.fontMono = .spaceMono
            s.displayShift = -200; s.figureWeight = 900
            s.capsLabels = true; s.monoLabels = true; s.monoTags = true; s.tracking = 1
            s.radiusScale = 0.9; s.pillRadius = 999; s.roundRadius = 999; s.dotRadius = 999; s.barRadius = 999
            s.rows = .dotted; s.badge = .marker
            s.chrome = .topbar; s.minWidth = 1040; s.gap = 12
            s.padLead = 40; s.padTrail = 40; s.padTop = 20; s.padBottom = 32

        case .swiss:
            s.bg = 0x0B0B0A; s.tile = 0x0B0B0A; s.inset = 0x161614; s.insetHover = 0x1F1F1C; s.well = 0x121210
            s.line = 0x3A3A37; s.rule = 0x2A2A27; s.edge = 0x5A5A55
            s.text = 0xF4F3EE; s.text2 = 0xC9C8C1; s.text3 = 0x9A9993; s.dim = 0x5F5E58
            s.accent = 0xFF3B1F; s.accentHover = 0xFF7A63; s.accentInk = 0x0B0B0A; s.accentText = 0xFF3B1F
            s.red = 0xFF3B1F; s.amber = 0xF5A623; s.green = 0x6FCF97; s.blue = 0x6CA6E0; s.spark = 0x3A3A37
            s.onFill = 0x0B0B0A; s.warnFill = 0xF5A623; s.warnInk = 0x0B0B0A
            s.heroFilled = false; s.hero = [0xF4F3EE, 0xFF3B1F, 0xFF3B1F]
            s.fontDisplay = .interTight; s.fontFigure = .interTight; s.fontUI = .interTight; s.fontMono = .systemMono
            s.displayShift = 100
            s.radiusScale = 0; s.pillRadius = 0; s.roundRadius = 0; s.dotRadius = 0; s.barRadius = 0
            s.panelKind = .ruled; s.ruleWidth = 1
            s.tilePadMax = 16
            s.fieldBorder = 0x5A5A55
            s.rows = .solid; s.badge = .plain; s.switchBlock = true
            s.chrome = .sidebar; s.minWidth = 1100; s.gap = 22
            s.padLead = 40; s.padTrail = 40; s.padTop = 38; s.padBottom = 28

        case .hardware:
            s.bg = 0x121211; s.tile = 0x1F1F1D; s.inset = 0x2A2A27; s.insetHover = 0x33332F; s.well = 0x141413
            s.line = 0x2C2C28; s.rule = 0x2C2C28; s.edge = 0x36362F
            s.text = 0xE7E5DE; s.text2 = 0xB8B6AE; s.text3 = 0x9C9A92; s.dim = 0x4A4A44
            s.accent = 0xFF6A2B; s.accentHover = 0xFF7D45; s.accentInk = 0x1A0C05; s.accentText = 0xFF6A2B
            s.red = 0xFF5A4E; s.amber = 0xF2B33D; s.green = 0x7BD389; s.blue = 0x7DB4E8; s.spark = 0x2F2F2B
            s.onFill = 0x1A0C05; s.warnFill = 0xF2B33D; s.warnInk = 0x1A1306
            s.heroFilled = false; s.hero = [0x7BD389, 0xF2B33D, 0xFF5A4E]
            s.fontDisplay = .plexSans; s.fontFigure = .plexSans; s.fontUI = .plexSans; s.fontMono = .plexMono
            s.displayShift = -100
            s.capsLabels = true; s.monoLabels = true; s.monoTags = true; s.tracking = 0.8
            s.radiusScale = 0.6; s.pillRadius = 8; s.roundRadius = 999; s.dotRadius = 999; s.barRadius = 1
            s.panelEmboss = true
            s.tilePadMax = 20
            s.rows = .solid; s.badge = .marker
            s.chrome = .sidebar; s.minWidth = 1100; s.gap = 14; s.outer = 14
            s.padLead = 0; s.padTrail = 0; s.padTop = 0; s.padBottom = 0

        case .brutal:
            s.dark = false
            s.bg = 0xF4F4EF; s.tile = 0xFFFFFF; s.inset = 0xF0F0E8; s.insetHover = 0xFFF3B0; s.well = 0xF4F4EF
            s.line = 0xD6D6CF; s.rule = 0xD6D6CF; s.edge = 0x111111
            s.text = 0x111111; s.text2 = 0x3B3B38; s.text3 = 0x6B6B66; s.dim = 0xA8A8A0
            s.accent = 0xFFD93D; s.accentHover = 0xFFE46B; s.accentInk = 0x111111; s.accentText = 0x111111
            s.red = 0xE5382B; s.amber = 0xC98600; s.green = 0x2DBE6C; s.blue = 0x1B8AD6; s.spark = 0xD6D6CF
            s.onFill = 0x111111; s.warnFill = 0xFFD93D; s.warnInk = 0x111111
            s.heroFilled = true; s.hero = [0x34C77B, 0xFFD93D, 0xFF5A4E]
            s.heroInk = [0x111111, 0x111111, 0x111111]; s.heroSoft = [0x2E2E2C, 0x2E2E2C, 0x2E2E2C]
            s.fontDisplay = .spaceGrotesk; s.fontFigure = .spaceGrotesk; s.fontUI = .spaceGrotesk; s.fontMono = .spaceMono
            s.monoTags = true
            s.radiusScale = 0.65; s.pillRadius = 10; s.roundRadius = 8; s.dotRadius = 999; s.barRadius = 3
            s.panelBorder = 0x111111; s.panelBorderWidth = 2; s.panelShadow = 4
            s.tilePadMax = 22
            s.fieldBorder = 0x111111; s.fieldBorderWidth = 2
            s.rows = .dashed; s.pills = .sticker; s.badge = .sticker; s.switchBlock = true
            s.chrome = .sidebar; s.minWidth = 1100; s.gap = 18; s.outer = 18
            s.padLead = 0; s.padTrail = 8; s.padTop = 0; s.padBottom = 8
        }

        if !s.heroFilled {
            s.heroInk = [s.text, s.text, s.text]
            s.heroSoft = [s.text2, s.text2, s.text2]
        }
        return s
    }
}

// MARK: - Type
//
// Fonts are bundled in the app (variable files, or static weights). Weights on variable fonts
// are set through the font's own axes. Without the files (e.g. `swift run`) the system fonts
// stand in.

enum Typeface {
    private static let wght = 0x77676874 as NSNumber
    private static let opsz = 0x6F70737A as NSNumber

    private enum Source {
        case variable(String, opsz: ClosedRange<CGFloat>?)
        case statics([(weight: CGFloat, file: String)])
        case system(mono: Bool)
    }

    private static func source(_ face: FontFace) -> Source {
        switch face {
        case .bricolage: .variable("BricolageGrotesque", opsz: 12...96)
        case .inter: .variable("Inter", opsz: 14...32)
        case .geist: .variable("Geist", opsz: nil)
        case .geistMono: .variable("GeistMono", opsz: nil)
        case .doto: .variable("Doto", opsz: nil)
        case .spaceGrotesk: .variable("SpaceGrotesk", opsz: nil)
        case .interTight: .variable("InterTight", opsz: nil)
        case .plexSans: .variable("IBMPlexSans", opsz: nil)
        case .jetbrains: .statics([(400, "JetBrainsMono-Regular"), (500, "JetBrainsMono-Medium"),
                                   (700, "JetBrainsMono-Bold"), (800, "JetBrainsMono-ExtraBold")])
        case .spaceMono: .statics([(400, "SpaceMono-Regular"), (700, "SpaceMono-Bold")])
        case .plexMono: .statics([(400, "IBMPlexMono-Regular"), (500, "IBMPlexMono-Medium"), (600, "IBMPlexMono-SemiBold")])
        case .systemSans: .system(mono: false)
        case .systemMono: .system(mono: true)
        }
    }

    private static var descriptors: [String: CTFontDescriptor?] = [:]
    private static var cache: [String: Font] = [:]

    private static func descriptor(_ file: String) -> CTFontDescriptor? {
        if let hit = descriptors[file] { return hit }
        var found: CTFontDescriptor?
        if let url = Bundle.main.url(forResource: file, withExtension: "ttf"),
           let list = CTFontManagerCreateFontDescriptorsFromURL(url as CFURL) as? [CTFontDescriptor] {
            found = list.first
        }
        descriptors[file] = found
        return found
    }

    static func font(_ face: FontFace, _ size: CGFloat, _ weight: CGFloat) -> Font {
        let key = "\(face)/\(size)/\(weight)"
        if let hit = cache[key] { return hit }
        let font: Font
        switch source(face) {
        case let .variable(file, range):
            if let base = descriptor(file) {
                var variations: [NSNumber: NSNumber] = [wght: NSNumber(value: Double(weight))]
                if let range {
                    variations[opsz] = NSNumber(value: Double(min(max(size, range.lowerBound), range.upperBound)))
                }
                let attrs = [kCTFontVariationAttribute: variations] as CFDictionary
                font = Font(CTFontCreateWithFontDescriptor(CTFontDescriptorCreateCopyWithAttributes(base, attrs), size, nil))
            } else {
                font = .system(size: size, weight: systemWeight(weight))
            }
        case let .statics(files):
            let pick = files.min { abs($0.weight - weight) < abs($1.weight - weight) }
            if let file = pick?.file, let d = descriptor(file) {
                font = Font(CTFontCreateWithFontDescriptor(d, size, nil))
            } else {
                font = .system(size: size, weight: systemWeight(weight), design: .monospaced)
            }
        case let .system(mono):
            font = .system(size: size, weight: systemWeight(weight), design: mono ? .monospaced : .default)
        }
        cache[key] = font
        return font
    }

    static func systemWeight(_ w: CGFloat) -> Font.Weight {
        switch w {
        case ..<350: .light
        case ..<450: .regular
        case ..<550: .medium
        case ..<650: .semibold
        case ..<750: .bold
        default: .heavy
        }
    }
}

extension Font {
    private static func half(_ v: CGFloat) -> CGFloat { (v * 2).rounded() / 2 }

    /// Headlines.
    static func display(_ size: CGFloat, _ weight: CGFloat = 700) -> Font {
        let s = Theme.skin
        return Typeface.font(s.fontDisplay, half(size * s.displayScale), weight + s.displayShift)
    }
    /// Big numbers. Dot Matrix draws them as dots.
    static func figure(_ size: CGFloat, _ weight: CGFloat = 700) -> Font {
        let s = Theme.skin
        // Dotted numerals fall apart when small; use the mono face for those.
        if s.fontFigure == .doto && size < 26 { return mono(size * 0.95, .bold) }
        return Typeface.font(s.fontFigure, half(size * s.figureScale), s.figureWeight ?? (weight + s.displayShift))
    }
    /// Everything you read.
    static func ui(_ size: CGFloat, _ weight: CGFloat = 400) -> Font {
        let s = Theme.skin
        return Typeface.font(s.fontUI, half(size * s.uiScale), weight)
    }
    /// Small captions that some looks set in the mono face.
    static func label(_ size: CGFloat, _ weight: CGFloat = 500) -> Font {
        Theme.skin.monoLabels ? mono(size * 0.92, weight >= 600 ? .semibold : weight >= 500 ? .medium : .regular) : ui(size, weight)
    }
    /// Pills and badges.
    static func tag(_ size: CGFloat, _ weight: CGFloat = 500) -> Font {
        Theme.skin.monoTags ? mono(size * 0.92, weight >= 700 ? .bold : weight >= 600 ? .semibold : weight >= 500 ? .medium : .regular)
                            : ui(size, weight)
    }
    static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        let w: CGFloat
        switch weight {
        case .bold, .heavy, .black: w = 700
        case .semibold: w = 600
        case .medium: w = 500
        default: w = 400
        }
        return Typeface.font(Theme.skin.fontMono, size, w)
    }
}
