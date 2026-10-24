import SwiftUI

/// iOS-style Control Center, recreated inside the RyBox shell.
///
/// Triggered by a long-press on the (fake) status bar. The toggles are
/// cosmetic — a sandboxed container cannot actually flip Wi-Fi/Bluetooth — but
/// they track local state so the panel feels real, and the brightness/volume
/// sliders are presented exactly like the system ones. A tap on the dimming
/// backdrop or a downward drag dismisses it.
struct ControlCenterView: View {
    var onDismiss: () -> Void

    @State private var airplane = false
    @State private var cellular = true
    @State private var wifi = true
    @State private var bluetooth = true
    @State private var airdrop = true
    @State private var rotationLock = false
    @State private var torch = false
    @State private var dnd = false

    @State private var brightness: Double = 0.72
    @State private var volume: Double = 0.4

    @State private var dragY: CGFloat = 0

    private let tile = (UIScreen.main.bounds.width < 500) ? 52.0 : 60.0

    var body: some View {
        ZStack {
            Color.black.opacity(0.001)
                .ignoresSafeArea()
                .onTapGesture { withAnimation(.easeOut(duration: 0.2)) { onDismiss() } }

            VStack(spacing: 18) {
                Spacer(minLength: 0)

                HStack(alignment: .top, spacing: 14) {
                    // Left column: the two big connectivity circles + sliders.
                    VStack(spacing: 14) {
                        HStack(spacing: 14) {
                            connCircle(active: airplane, on: airplane,
                                       color: .orange, icon: "airplane", label: "飞行模式")
                            connCircle(active: cellular, on: cellular,
                                       color: .green, icon: "antenna.radiowaves.left.and.right", label: "蜂窝")
                        }
                        sliderRow(kind: .brightness)
                        sliderRow(kind: .volume)
                    }
                    .frame(width: tile * 2 + 14)

                    // Right column: 2x2 + 2 toggles.
                    VStack(spacing: 14) {
                        HStack(spacing: 14) {
                            connCircle(active: wifi, on: wifi, color: .blue,
                                       icon: "wifi", label: "无线局域网")
                            connCircle(active: bluetooth, on: bluetooth, color: .blue,
                                       icon: "bluetooth", label: "蓝牙")
                        }
                        HStack(spacing: 14) {
                            connCircle(active: airdrop, on: airdrop, color: .blue,
                                       icon: "personalhotspot", label: "个人热点")
                            connCircle(active: rotationLock, on: rotationLock, color: .red,
                                       icon: "lock.rotation", label: "旋转锁定")
                        }
                        HStack(spacing: 14) {
                            connCircle(active: torch, on: torch, color: .white,
                                       icon: "flashlight.on.fill", label: "手电筒")
                            connCircle(active: dnd, on: dnd, color: .red,
                                       icon: "moon.fill", label: "勿扰")
                        }
                    }
                }
                .padding(16)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 30, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 30, style: .continuous)
                        .strokeBorder(.white.opacity(0.18), lineWidth: 0.6)
                )

                Spacer(minLength: 0)
            }
            .padding(.horizontal, 16)
            .padding(.top, 50)
            .offset(y: dragY)
            .gesture(
                DragGesture()
                    .onChanged { dragY = max(0, $0.translation.height) }
                    .onEnded { if $0.translation.height > 60 { withAnimation(.easeOut(duration: 0.2)) { onDismiss() } } else { dragY = 0 } }
            )
        }
        .ignoresSafeArea()
    }

    // MARK: Connectivity circle

    private func connCircle(active: Bool, on: Bool, color: Color, icon: String, label: String) -> some View {
        VStack(spacing: 4) {
            Button(action: {
                switch label {
                case "飞行模式": airplane.toggle()
                case "蜂窝": cellular.toggle()
                case "无线局域网": wifi.toggle()
                case "蓝牙": bluetooth.toggle()
                case "个人热点": airdrop.toggle()
                case "旋转锁定": rotationLock.toggle()
                case "手电筒": torch.toggle()
                case "勿扰": dnd.toggle()
                default: break
                }
            }) {
                Image(systemName: icon)
                    .font(.system(size: tile * 0.34, weight: .medium))
                    .foregroundStyle(.white)
                    .frame(width: tile, height: tile)
                    .background(on ? color : Color.white.opacity(0.16),
                                in: Circle())
            }
            .buttonStyle(.plain)
            Text(label)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(.white.opacity(0.7))
        }
    }

    // MARK: Sliders

    private enum SliderKind { case brightness, volume }

    private func sliderRow(kind: SliderKind) -> some View {
        HStack(spacing: 10) {
            Image(systemName: kind == .brightness ? "sun.max.fill" : "speaker.wave.2.fill")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.white)
            Slider(value: kind == .brightness ? $brightness : $volume, in: 0...1)
                .tint(kind == .brightness ? .white : .white)
            Image(systemName: kind == .brightness ? "sun.max.fill" : "speaker.wave.3.fill")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(.white)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color.white.opacity(0.16), in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}
