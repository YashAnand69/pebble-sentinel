# Web frontend third-party notices

Original Pebble Sentinel application code and authored visual assets are licensed under the repository's MIT license. The following unmodified dependencies and font assets retain their own licenses; they are not relicensed by the application.

| Component | Installed version | License | Attribution and source |
|---|---|---|---|
| React and React DOM | 19.2.0 | MIT | Copyright Meta Platforms, Inc. and affiliates; https://github.com/facebook/react |
| Lucide React icons | 0.468.0 | ISC, with Feather portions under MIT | Copyright Lucide Contributors 2022; Feather portions copyright Cole Bemis 2013–2022; https://github.com/lucide-icons/lucide |
| DM Sans font assets, packaged by Fontsource | @fontsource/dm-sans 5.3.0; font v17 | SIL Open Font License 1.1 | Copyright 2014 The DM Sans Project Authors; https://github.com/googlefonts/dm-fonts |
| Space Grotesk font assets, packaged by Fontsource | @fontsource/space-grotesk 5.3.0; font v22 | SIL Open Font License 1.1 | Copyright 2020 The Space Grotesk Project Authors; https://github.com/floriankarsten/space-grotesk |

Fonts are self-hosted by this application. No font request is sent to Google Fonts. Full font licenses, including their original copyright statements, are preserved in [DM-Sans-OFL.txt](public/licenses/DM-Sans-OFL.txt) and [Space-Grotesk-OFL.txt](public/licenses/Space-Grotesk-OFL.txt). They are also copied unchanged into each production build's `/licenses/` directory.

React's full notice is in [React-MIT.txt](public/licenses/React-MIT.txt). Lucide's installed full notice is in [Lucide-ISC.txt](public/licenses/Lucide-ISC.txt). The production JavaScript also retains dependency license comments where emitted by the bundler.

Build tooling remains subject to its package licenses; exact installed versions and dependency provenance are recorded in `package-lock.json`. Fontsource's package metadata identifies its font distributions as OFL-1.1; no claim is made that the font binaries are MIT.
