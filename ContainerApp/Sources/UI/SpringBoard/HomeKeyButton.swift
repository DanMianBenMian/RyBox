import SwiftUI

/// THE home key — one design, two hosts.
///
/// The SpringBoard renders this view directly (`SpringBoardView.homeKey`).
/// While a guest owns the screen, the floating chrome window
/// (`GuestChromeWindow`) hosts THE SAME view through a UIHostingController —
/// so the key the user taps on top of a guest app is pixel-identical to the
/// one on the desktop. They used to be two separately hand-drawn controls (a
/// 46pt SwiftUI liquid-glass square vs a 48pt UIKit pill), which is exactly
/// what the user called out on 2026-10-25: 「为啥要两种不同的Home键，直接用
/// SpringBoard就行，一直置于顶部即可。」
///
/// Visual spec (frozen — do not "improve" one side only):
///   46×46 square · .ultraThinMaterial · continuous cornerRadius 13 ·
///   house.fill 17pt semibold · foreground .primary ·
///   white stroke 30% @ 0.6pt · shadow black 28% radius 9 y3 ·
///   bottom-center, 4pt above the safe-area bottom.
struct HomeKeyButton: View {
    /// Tap: go home (SpringBoard resets / guest tears down).
    var action: () -> Void
    /// Edit mode swaps the glyph for a checkmark (SpringBoard only; the guest
    /// chrome has no edit mode).
    var showsCheckmark: Bool = false

    var body: some View {
        Button(action: action) {
            Image(systemName: showsCheckmark ? "checkmark" : "house.fill")
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(.primary)
                .frame(width: 46, height: 46)
                .background(
                    .ultraThinMaterial,
                    in: RoundedRectangle(cornerRadius: 13, style: .continuous)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .strokeBorder(.white.opacity(0.30), lineWidth: 0.6)
                )
                .shadow(color: .black.opacity(0.28), radius: 9, y: 3)
        }
        .buttonStyle(.plain)
        // The key itself is the only hit area; the surrounding frame must not
        // swallow taps meant for the guest underneath (the chrome window's
        // PassThroughView relies on that).
        .contentShape(Rectangle())
    }
}
