import AppKit
import SwiftUI

/// Screenshot tests: a SwiftUI view is hosted in an off-screen window, drawn into a bitmap of fixed pixel size and
/// compared with the committed golden `Tests/Fixtures/screenshots/<name>.png`.
///
/// Environment:
///   SNAPSHOT_RECORD=1   write the rendered image as the golden instead of comparing (see scripts/test-ui.sh --record)
///   SNAPSHOT_OUT=<dir>  where `actual/` and `diff/` images of failures go (default build/screenshots)
///
/// Goldens depend on the OS version and its font rendering, so they are recorded on the CI runner (workflow
/// "Record screenshot goldens"), not on a developer's Mac.
enum Snapshot {
    static let pixelScale = 2  // fixed, whatever display the machine has
    /// A pixel differs when any channel differs by more than this (0-255)...
    static let channelTolerance = 10
    /// ...and the test fails when more than this share of pixels differ.
    static let maxDifferingRatio = 0.004

    static var recording: Bool { ProcessInfo.processInfo.environment["SNAPSHOT_RECORD"] == "1" }
    static let goldenDir: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/screenshots", isDirectory: true)
    static var outDir: URL {
        URL(fileURLWithPath: ProcessInfo.processInfo.environment["SNAPSHOT_OUT"] ?? "build/screenshots", isDirectory: true)
    }

    struct Pixels {
        var width: Int, height: Int
        var data: [UInt8]  // RGBA, premultiplied, row-major
    }

    /// Draws `view` at `size` (points) in the given color scheme (the system scheme is ignored on purpose).
    @MainActor static func render<V: View>(_ view: V, size: CGSize, dark: Bool = false) -> NSBitmapImageRep {
        let root =
            view
            .environment(\.colorScheme, dark ? .dark : .light)
            .environment(\.locale, Locale(identifier: "en_US"))
            .environment(\.timeZone, TimeZone(identifier: "UTC")!)
            .frame(width: size.width, height: size.height)
        let host = NSHostingView(rootView: root)
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.titled], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        window.contentView = host
        window.setContentSize(size)
        // Let SwiftUI lay out and populate AppKit-backed controls (Table, TabView, Form) before drawing.
        for _ in 0..<6 {
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: Int(size.width) * pixelScale, pixelsHigh: Int(size.height) * pixelScale,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .calibratedRGB,
            bytesPerRow: 0, bitsPerPixel: 32)!
        rep.size = size
        host.cacheDisplay(in: host.bounds, to: rep)
        window.contentView = nil
        return rep
    }

    static func pixels(of rep: NSBitmapImageRep) -> Pixels? {
        guard let cg = rep.cgImage else { return nil }
        let w = cg.width, h = cg.height
        var data = [UInt8](repeating: 0, count: w * h * 4)
        let ok = data.withUnsafeMutableBytes { buf -> Bool in
            guard
                let ctx = CGContext(
                    data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
            else { return false }
            ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }
        return ok ? Pixels(width: w, height: h, data: data) : nil
    }

    static func png(_ p: Pixels) -> Data? {
        var d = p.data
        let cg: CGImage? = d.withUnsafeMutableBytes { buf in
            CGContext(
                data: buf.baseAddress, width: p.width, height: p.height, bitsPerComponent: 8, bytesPerRow: p.width * 4,
                space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)?.makeImage()
        }
        guard let cg else { return nil }
        return NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])
    }

    /// Number of distinct colors (capped): a view that failed to draw leaves one flat color.
    static func distinctColors(_ p: Pixels) -> Int {
        var seen = Set<UInt32>()
        var i = 0
        while i + 3 < p.data.count, seen.count <= 64 {
            seen.insert(UInt32(p.data[i]) << 24 | UInt32(p.data[i + 1]) << 16 | UInt32(p.data[i + 2]) << 8 | UInt32(p.data[i + 3]))
            i += 4
        }
        return seen.count
    }

    /// Returns nil when the image matches its golden (or was recorded), else a message.
    @MainActor static func check<V: View>(_ name: String, _ view: V, size: CGSize, dark: Bool = false) -> String? {
        let rep = render(view, size: size, dark: dark)
        guard let actual = pixels(of: rep), let actualPNG = png(actual) else { return "\(name): could not rasterize the view" }
        let colors = distinctColors(actual)
        if colors < 8 { return "\(name): the rendered frame is blank (\(colors) colors); the view did not draw" }
        let fm = FileManager.default
        let golden = goldenDir.appendingPathComponent("\(name).png")
        if recording {
            try? fm.createDirectory(at: goldenDir, withIntermediateDirectories: true)
            do { try actualPNG.write(to: golden) } catch { return "\(name): cannot write \(golden.path): \(error)" }
            print("    recorded \(name).png (\(actual.width)x\(actual.height))")
            return nil
        }
        func saveActual() -> String {
            let dir = outDir.appendingPathComponent("actual")
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
            let url = dir.appendingPathComponent("\(name).png")
            try? actualPNG.write(to: url)
            return url.path
        }
        guard let goldenData = try? Data(contentsOf: golden), let goldenRep = NSBitmapImageRep(data: goldenData),
            let expected = pixels(of: goldenRep)
        else {
            return "\(name): no golden at Tests/Fixtures/screenshots/\(name).png (actual image: \(saveActual())). "
                + "Record goldens with the \"Record screenshot goldens\" workflow and commit them."
        }
        guard expected.width == actual.width, expected.height == actual.height else {
            return "\(name): size \(actual.width)x\(actual.height) differs from the golden \(expected.width)x\(expected.height) (actual: \(saveActual()))"
        }
        var differing = 0
        var diff = Pixels(width: actual.width, height: actual.height, data: [UInt8](repeating: 255, count: actual.data.count))
        for px in 0..<(actual.width * actual.height) {
            let i = px * 4
            var maxDelta = 0
            for c in 0..<4 { maxDelta = max(maxDelta, abs(Int(actual.data[i + c]) - Int(expected.data[i + c]))) }
            if maxDelta > channelTolerance {
                differing += 1
                diff.data[i] = 255; diff.data[i + 1] = 0; diff.data[i + 2] = 0
            } else {  // faded copy of the golden for context
                for c in 0..<3 { diff.data[i + c] = UInt8(200 + Int(expected.data[i + c]) / 5) }
            }
        }
        let ratio = Double(differing) / Double(actual.width * actual.height)
        if ratio <= maxDifferingRatio { return nil }
        let diffDir = outDir.appendingPathComponent("diff")
        try? fm.createDirectory(at: diffDir, withIntermediateDirectories: true)
        let diffURL = diffDir.appendingPathComponent("\(name).png")
        if let d = png(diff) { try? d.write(to: diffURL) }
        return "\(name): \(differing) pixels differ (\(String(format: "%.2f", ratio * 100))% > \(maxDifferingRatio * 100)%); "
            + "actual: \(saveActual()), diff: \(diffURL.path)"
    }
}
