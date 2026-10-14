# PW-Manager fürs iPhone

Die Web-App zum PW-Manager: Sie öffnet deinen verschlüsselten Tresor (`vault.pwmv`)
auf dem iPhone und entschlüsselt ihn nur auf dem Gerät (Argon2id + AES-256-GCM).
Dieses Repo enthält nur den Programmcode, keine Passwörter und keine Schlüssel.

Öffnen: **https://lukeluke25811.github.io/PW-Manager-Public/** in Safari, dann
Teilen → **Zum Home-Bildschirm**.

So kommt der Tresor aufs iPhone: im PW-Manager am PC **File → Save encrypted backup**
in einen Ordner in iCloud Drive oder OneDrive speichern und in der App
„Tresordatei wählen" antippen.

Diese Version kann nur lesen: suchen, Benutzername und Passwort kopieren, Website öffnen.
Sie sperrt sich nach der Zeit aus den Tresor-Einstellungen und spätestens 2 Minuten,
nachdem du sie verlassen hast.

`vendor/argon2.umd.min.js` ist [hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0
(MIT-Lizenz, siehe `vendor/hash-wasm-LICENSE.txt`).

Veröffentlicht wird der Branch `gh-pages`. Neue Versionen dorthin pushen.
