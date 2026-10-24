CODESIGN HELPER — required at runtime
================================================================================

RyBox re-signs every guest binary on-device with the user's own certificate
(distribution or development). It does NOT bypass AMFI — it satisfies AMFI with a
legitimate signature. The Mach-O signing itself is delegated to a bundled
auxiliary executable named "codesign" that lives in the app bundle root.


WHY A SEPARATE BINARY?
--------------------------------------------------------------------------------
The iOS SDK does not expose an API to ad-hoc re-sign an arbitrary Mach-O on
device. So we bundle a small, already-signed command-line signer (itself signed
by RyBox's build cert) and call it via posix_spawn. It re-signs guest binaries
with the user-imported p12 + mobileprovision at runtime.


THE CONTRACT (what CodeSigner.swift calls)
--------------------------------------------------------------------------------
CodeSigner stages p12 / mobileprovision / entitlements into a temp dir, embeds
the provisioning profile as embedded.mobileprovision, then invokes:

    codesign --p12 <p12Path> --password <pw> --prov <mobileprovisionPath>
             [--entitlements <entitlementsPlistPath>] --bundle <appBundlePath>

Requirements on the helper:
  * Signs the given .app bundle IN PLACE (main executable + nested
    Frameworks/*.framework, PlugIns/*.appex, bundled .dylib).
  * Embeds the provisioning profile (already done by CodeSigner, but the helper
    must not strip it).
  * Uses the supplied entitlements (already derived from the provisioning
    profile's embedded Entitlements dict — application-identifier,
    get-task-allow=false, keychain-access-groups, ...).
  * Exit code 0 == success.


HOW TO OBTAIN THE BINARY (pick one)
--------------------------------------------------------------------------------
1) zsign (recommended, simplest). Build zsign for iOS arm64 (a maintained fork
   such as zhlynn/zsign or a CI-built binary), then rename the output to
   "codesign" and drop it into the app bundle root. zsign natively takes
   -k/-p/-m/-e and re-signs a whole .app in place.

2) ldid wrapper. ldid itself signs with a keychain identity, so wrap it:
   import the p12 into a temporary keychain, then call
   `ldid -S<entitlements> -K<key> <binary>` per Mach-O. Provide this wrapper
   under the name "codesign" honoring the contract above.

3) Nyxian's bundled signer, or any equivalent self-contained iOS signer.


WHERE TO PLACE IT
--------------------------------------------------------------------------------
The binary must resolve via either:
  Bundle.main.url(forAuxiliaryExecutable: "codesign")
or (fallback used by CodeSigner) the app-bundle root:
  RyBox.app/codesign

Recommended: copy it to ContainerApp/ContainerApp/codesign (app root) so it is
packaged into the .app. Mark it executable in the build (it already is once
built for the platform).

NOTE: because this binary is inside RyBox's bundle, it is signed by RyBox's own
build certificate at archive time and runs as a child of RyBox with no extra
AMFI friction. It only RE-SIGNS guest binaries with the USER's cert.


NO SOURCE IDE / COMPILER IS BUNDLED (per project scope)
--------------------------------------------------------------------------------
RyBox is a runtime microkernel environment, not a toolchain. The host signs
guests; it does not compile them. The "codesign" helper above is the only
external prebuilt binary required.
