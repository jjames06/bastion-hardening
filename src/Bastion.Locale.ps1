# =============================================================================
# Bastion.Locale.ps1 - UI language tables (menu numbers and key terms stay English)
# =============================================================================
# Dot-sourced after Init, before Core. Do not run standalone.
# Default language is English so website help screenshots stay accurate.
# Optional languages: de, es, fr. Product terms Dry Run, Apply, Recovery,
# StrictHandle, YES remain English in every language.
# =============================================================================

$script:BastionUiLanguage = "en"
$script:BastionTextEn = $null
$script:BastionText = $null

function Get-BastionLocaleCatalog {
    param([string]$Lang)
    $en = @{
        "menu.review" = "REVIEW (no changes)"
        "menu.configure" = "CONFIGURE (save choices; Windows not changed yet)"
        "menu.execute" = "EXECUTE (makes system changes)"
        "menu.maintain" = "MAINTAIN (actions run NOW)"
        "menu.safety" = "SAFETY (do this first)"
        "menu.system" = "SYSTEM"
        "menu.1" = "   1    Dry Run (preview only)"
        "menu.2" = "   2    Security audit"
        "menu.3" = "   3    Hardware and driver guidance"
        "menu.4" = "   4    Hardening sections"
        "menu.5" = "   5    Programs and install paths"
        "menu.6" = "   6    Browser privacy policies (applies NOW to chosen browsers)"
        "menu.D" = "   D    DNS resolver (preference; Apply via A inside D, or 8)"
        "menu.7" = "   7    Quick Harden (guided preset + Apply)"
        "menu.8" = "   8    Apply Hardening (run enabled sections + install queue)"
        "menu.9" = "   9    Recovery / fix"
        "menu.10" = "  10    Uninstall programs"
        "menu.13" = "  13    Create / name a System Restore Point"
        "menu.R" = "   R    Same as 13 (shortcut)"
        "menu.11" = "  11    Help and reports"
        "menu.12" = "  12    Reset Bastion config only"
        "menu.L" = "   L    Language (numbers stay the same; handbook screenshots are English)"
        "menu.0" = "   0    Exit"
        "menu.select" = "  Select"
        "menu.flow" = "  Flow: configure (4/5/D) -> Dry Run (1) optional -> restore point (13) -> Apply (8)."
        "menu.exception6" = "  Exception: menu 6 browser policies apply as soon as you confirm a mode."
        "menu.installs" = "  Installs: catalog IDs only; winget hash enforced. GPU/BIOS: option 3 is guidance only."
        "menu.queued" = "  Programs queued to install: {0}"
        "menu.none" = "None"
        "status.dataDir" = "  Data directory: {0}"
        "status.firstRun" = "  First run (or wiped store): defaults seeded. No prior Bastion config was found."
        "status.loaded" = "  Config loaded from previous session."
        "status.defaults" = "  Config: using in-memory defaults (file missing or unreadable)."
        "status.lastApply" = "  Last Bastion Apply: {0} (v{1}){2}{3}"
        "status.noApply" = "  No Bastion Apply recorded yet (live OS detection still drives Dry Run / Apply)."
        "status.browser" = "  Browser policies: {0}"
        "status.dns" = "  DNS resolver:   {0}"
        "restore.ok" = "  Restore status: recent point OK ({0})"
        "restore.tip" = "  Tip: still create a fresh point with 13 / R before major Apply runs."
        "restore.old" = "  Restore status: points exist, but none in the last 48 hours."
        "restore.oldAction" = "  Action: press 13 or R to create a named point before Apply / Quick Harden."
        "restore.none" = "  Restore status: NONE found on this PC."
        "restore.noneAction" = "  Action: press 13 or R BEFORE Apply, Quick Harden, or BloatApps."
        "restore.queryFail" = "  Restore status: could not query System Restore."
        "restore.check" = "  Check System Protection is on for the system drive (sysdm.cpl > System Protection)."
        "dns.snap" = "; encrypted DNS snapshot available"
        "rdp.prior" = "; RDP host prior saved"
        "applies.now" = "  Takes effect: NOW from this menu (no main menu 8 needed)."
        "applies.m8" = "  Takes effect: after main menu 8 (Apply Hardening)."
        "applies.pref" = "  Preference: saved immediately."
        "applies.dns" = "  Windows DNS: only after Apply - press A here, or main menu 8 (DNS section on)."
        "input.tooManyN" = "  Too many invalid inputs; defaulting to N."
        "input.yn" = "  Input error. Enter Y or N."
        "input.ynOnly" = "  Invalid input. Enter Y or N only."
        "input.tooManyCancel" = "  Too many invalid inputs; cancelling."
        "input.yesNo" = "  Input error. Type YES to confirm, or NO to cancel."
        "input.yesOnly" = "  Invalid input. Type YES (all caps) to confirm, or NO to cancel."
        "input.menuNone" = "  Internal error: no valid choices configured."
        "input.menuGiveUp" = "  Too many invalid inputs; returning cancel (0) if available."
        "hdr.recovery" = "RECOVERY / FIX"
        "hdr.hardware" = "HARDWARE AND DRIVER GUIDANCE"
        "hdr.programs" = "PROGRAMS AND INSTALL PATHS"
        "hdr.sections" = "HARDENING SECTIONS"
        "hdr.dns" = "DNS RESOLVER"
        "hdr.browser" = "BROWSER PRIVACY POLICIES"
        "hdr.uninstall" = "UNINSTALL"
        "hdr.help" = "HELP AND REPORTS"
        "hdr.language" = "LANGUAGE"
        "rec.1" = "  1  Undo last Apply (tracked services, firewall groups, DNS snapshot, RDP prior)"
        "rec.2" = "  2  Services (Print Spooler, high-risk stack, Xbox)"
        "rec.3" = "  3  Network (remote access, LAN discovery, DNS DHCP / restore snapshot)"
        "rec.4" = "  4  Browser policies (per browser; Default reverts Bastion policies)"
        "rec.5" = "  5  Apps and UI (Copilot, Widgets/Suggestions, Game Bar)"
        "rec.6" = "  6  Security mitigations (StrictHandle, Defender, LSA, policies/tasks)"
        "rec.0" = "  0  Back"
        "rec.notes" = "  Notes:"
        "rec.n1" = "Hubs show live status first, then offer reverse / re-harden actions"
        "rec.n2" = "Re-opening remote/LAN paths or services increases attack surface"
        "rec.n3" = "Appx bloat and OneDrive are not reinstallable here - System Restore or vendor installers"
        "rec.extra" = "Prefer a specific hub when you know what broke. Full Undo (1) is broader and still best-effort."
        "lang.intro" = "  Handbook and screenshots on operationlockedin.com stay English. Menu numbers do not change."
        "lang.terms" = "  Dry Run, Apply, Recovery, StrictHandle, and YES stay English in every language."
        "lang.1" = "  1  English"
        "lang.2" = "  2  Deutsch"
        "lang.3" = "  3  Espanol"
        "lang.4" = "  4  Francais"
        "lang.0" = "  0  Back"
        "lang.set" = "  Language set to {0}."
        "hw.noInstall" = "  Bastion does NOT install GPU drivers or flash BIOS."
    }

    $de = @{
        "menu.review" = "PRUEFEN (keine Aenderungen)"
        "menu.configure" = "KONFIGURIEREN (Auswahl speichern; Windows noch unveraendert)"
        "menu.execute" = "AUSFUEHREN (aendert das System)"
        "menu.maintain" = "WARTUNG (Aktionen gelten JETZT)"
        "menu.safety" = "SICHERHEIT (zuerst hier)"
        "menu.system" = "SYSTEM"
        "menu.1" = "   1    Dry Run (nur Vorschau)"
        "menu.2" = "   2    Security audit"
        "menu.3" = "   3    Hardware- und Treiberhinweise"
        "menu.4" = "   4    Haertungsabschnitte"
        "menu.5" = "   5    Programme und Installationspfade"
        "menu.6" = "   6    Browser-Datenschutzrichtlinien (gilt JETZT fuer gewaehlte Browser)"
        "menu.D" = "   D    DNS resolver (Vorgabe; Apply mit A in D, oder 8)"
        "menu.7" = "   7    Quick Harden (gefuehrte Vorgabe + Apply)"
        "menu.8" = "   8    Apply Hardening (aktive Abschnitte + Installationsliste)"
        "menu.9" = "   9    Recovery / fix"
        "menu.10" = "  10    Programme deinstallieren"
        "menu.13" = "  13    Systemwiederherstellungspunkt anlegen / benennen"
        "menu.R" = "   R    Wie 13 (Kuerzel)"
        "menu.11" = "  11    Hilfe und Berichte"
        "menu.12" = "  12    Nur Bastion-Config zuruecksetzen"
        "menu.L" = "   L    Sprache (Nummern bleiben; Handbuch-Screenshots sind Englisch)"
        "menu.0" = "   0    Beenden"
        "menu.select" = "  Auswahl"
        "menu.flow" = "  Ablauf: konfigurieren (4/5/D) -> Dry Run (1) optional -> Punkt 13 -> Apply (8)."
        "menu.exception6" = "  Ausnahme: Menue 6 Browser-Richtlinien gelten, sobald Sie einen Modus bestaetigen."
        "menu.installs" = "  Installationen: nur Katalog-IDs; winget-Hash erzwungen. GPU/BIOS: Option 3 ist nur Hinweis."
        "menu.queued" = "  Programme in der Installationsliste: {0}"
        "menu.none" = "Keine"
        "status.dataDir" = "  Datenverzeichnis: {0}"
        "status.firstRun" = "  Erster Start (oder geleerter Store): Vorgaben gesetzt. Keine vorherige Bastion-Config gefunden."
        "status.loaded" = "  Config aus vorheriger Sitzung geladen."
        "status.defaults" = "  Config: Vorgabewerte im Speicher (Datei fehlt oder unlesbar)."
        "status.lastApply" = "  Letztes Bastion Apply: {0} (v{1}){2}{3}"
        "status.noApply" = "  Noch kein Bastion Apply erfasst (Dry Run / Apply nutzen die live OS-Erkennung)."
        "status.browser" = "  Browser-Richtlinien: {0}"
        "status.dns" = "  DNS resolver:   {0}"
        "restore.ok" = "  Wiederherstellung: aktueller Punkt OK ({0})"
        "restore.tip" = "  Tipp: vor groesseren Apply-Laeufen trotzdem 13 / R fuer einen frischen Punkt."
        "restore.old" = "  Wiederherstellung: Punkte vorhanden, keiner in den letzten 48 Stunden."
        "restore.oldAction" = "  Aktion: 13 oder R fuer einen benannten Punkt vor Apply / Quick Harden."
        "restore.none" = "  Wiederherstellung: KEINEN Punkt auf diesem PC gefunden."
        "restore.noneAction" = "  Aktion: 13 oder R VOR Apply, Quick Harden oder BloatApps."
        "restore.queryFail" = "  Wiederherstellung: System Restore konnte nicht abgefragt werden."
        "restore.check" = "  Pruefen Sie Systemschutz fuer das Systemlaufwerk (sysdm.cpl > System Protection)."
        "applies.now" = "  Wirkt: JETZT aus diesem Menue (kein Hauptmenue 8 noetig)."
        "applies.m8" = "  Wirkt: nach Hauptmenue 8 (Apply Hardening)."
        "applies.pref" = "  Vorgabe: sofort gespeichert."
        "applies.dns" = "  Windows DNS: erst nach Apply - hier A, oder Hauptmenue 8 (DNS-Abschnitt an)."
        "input.tooManyN" = "  Zu viele ungueltige Eingaben; Vorgabe N."
        "input.yn" = "  Eingabefehler. Y oder N eingeben."
        "input.ynOnly" = "  Ungueltig. Nur Y oder N."
        "input.tooManyCancel" = "  Zu viele ungueltige Eingaben; Abbruch."
        "input.yesNo" = "  Eingabefehler. YES zum Bestaetigen, NO zum Abbrechen."
        "input.yesOnly" = "  Ungueltig. YES (Grossbuchstaben) zum Bestaetigen, oder NO zum Abbrechen."
        "input.menuNone" = "  Interner Fehler: keine gueltigen Auswahlwerte."
        "input.menuGiveUp" = "  Zu viele ungueltige Eingaben; Abbruch (0) falls vorhanden."
        "hdr.recovery" = "RECOVERY / FIX"
        "hdr.hardware" = "HARDWARE AND DRIVER GUIDANCE"
        "hdr.programs" = "PROGRAMS AND INSTALL PATHS"
        "hdr.sections" = "HARDENING SECTIONS"
        "hdr.dns" = "DNS RESOLVER"
        "hdr.browser" = "BROWSER PRIVACY POLICIES"
        "hdr.uninstall" = "UNINSTALL"
        "hdr.help" = "HELP AND REPORTS"
        "hdr.language" = "LANGUAGE"
        "rec.1" = "  1  Undo last Apply (tracked services, firewall groups, DNS snapshot, RDP prior)"
        "rec.2" = "  2  Services (Print Spooler, high-risk stack, Xbox)"
        "rec.3" = "  3  Network (remote access, LAN discovery, DNS DHCP / restore snapshot)"
        "rec.4" = "  4  Browser policies (per browser; Default reverts Bastion policies)"
        "rec.5" = "  5  Apps and UI (Copilot, Widgets/Suggestions, Game Bar)"
        "rec.6" = "  6  Security mitigations (StrictHandle, Defender, LSA, policies/tasks)"
        "rec.0" = "  0  Zurueck"
        "rec.notes" = "  Hinweise:"
        "rec.n1" = "Hubs zeigen zuerst den Live-Status, dann Ruecknahme / erneutes Haerten"
        "rec.n2" = "Remote-/LAN-Pfade oder Dienste wieder zu oeffnen vergroessert die Angriffsflaeche"
        "rec.n3" = "Appx-Ballast und OneDrive sind hier nicht neu installierbar - System Restore oder Hersteller"
        "rec.extra" = "Waehlen Sie einen konkreten Hub, wenn Sie wissen, was kaputt ist. Full Undo (1) ist breiter und trotzdem best-effort."
        "lang.intro" = "  Handbuch und Screenshots auf operationlockedin.com bleiben Englisch. Menue-Nummern aendern sich nicht."
        "lang.terms" = "  Dry Run, Apply, Recovery, StrictHandle und YES bleiben in jeder Sprache Englisch."
        "lang.1" = "  1  English"
        "lang.2" = "  2  Deutsch"
        "lang.3" = "  3  Espanol"
        "lang.4" = "  4  Francais"
        "lang.0" = "  0  Zurueck"
        "lang.set" = "  Sprache gesetzt: {0}."
        "hw.noInstall" = "  Bastion installiert KEINE GPU-Treiber und flasht kein BIOS."
    }

    $es = @{
        "menu.review" = "REVISAR (sin cambios)"
        "menu.configure" = "CONFIGURAR (guarda opciones; Windows aun no cambia)"
        "menu.execute" = "EJECUTAR (cambia el sistema)"
        "menu.maintain" = "MANTENER (acciones YA)"
        "menu.safety" = "SEGURIDAD (haga esto primero)"
        "menu.system" = "SISTEMA"
        "menu.1" = "   1    Dry Run (solo vista previa)"
        "menu.2" = "   2    Security audit"
        "menu.3" = "   3    Guia de hardware y controladores"
        "menu.4" = "   4    Secciones de endurecimiento"
        "menu.5" = "   5    Programas y rutas de instalacion"
        "menu.6" = "   6    Politicas de privacidad del navegador (aplica YA a los elegidos)"
        "menu.D" = "   D    DNS resolver (preferencia; Apply con A dentro de D, o 8)"
        "menu.7" = "   7    Quick Harden (preajuste guiado + Apply)"
        "menu.8" = "   8    Apply Hardening (secciones activas + cola de instalacion)"
        "menu.9" = "   9    Recovery / fix"
        "menu.10" = "  10    Desinstalar programas"
        "menu.13" = "  13    Crear / nombrar un punto de restauracion"
        "menu.R" = "   R    Igual que 13 (atajo)"
        "menu.11" = "  11    Ayuda e informes"
        "menu.12" = "  12    Restablecer solo la config de Bastion"
        "menu.L" = "   L    Idioma (los numeros no cambian; las capturas del manual estan en ingles)"
        "menu.0" = "   0    Salir"
        "menu.select" = "  Seleccionar"
        "menu.flow" = "  Flujo: configurar (4/5/D) -> Dry Run (1) opcional -> punto 13 -> Apply (8)."
        "menu.exception6" = "  Excepcion: el menu 6 aplica politicas de navegador en cuanto confirma un modo."
        "menu.installs" = "  Instalaciones: solo IDs de catalogo; hash de winget obligatorio. GPU/BIOS: la opcion 3 es solo guia."
        "menu.queued" = "  Programas en cola de instalacion: {0}"
        "menu.none" = "Ninguno"
        "status.dataDir" = "  Directorio de datos: {0}"
        "status.firstRun" = "  Primera ejecucion (o almacen vaciado): valores por defecto. No habia config previa."
        "status.loaded" = "  Config cargada de la sesion anterior."
        "status.defaults" = "  Config: valores en memoria (archivo ausente o ilegable)."
        "status.lastApply" = "  Ultimo Bastion Apply: {0} (v{1}){2}{3}"
        "status.noApply" = "  Aun no hay Apply registrado (Dry Run / Apply usan la deteccion live del SO)."
        "status.browser" = "  Politicas de navegador: {0}"
        "status.dns" = "  DNS resolver:   {0}"
        "restore.ok" = "  Restauracion: punto reciente OK ({0})"
        "restore.tip" = "  Consejo: cree igual un punto fresco con 13 / R antes de un Apply mayor."
        "restore.old" = "  Restauracion: hay puntos, pero ninguno en las ultimas 48 horas."
        "restore.oldAction" = "  Accion: pulse 13 o R para un punto con nombre antes de Apply / Quick Harden."
        "restore.none" = "  Restauracion: NINGUN punto en este PC."
        "restore.noneAction" = "  Accion: 13 o R ANTES de Apply, Quick Harden o BloatApps."
        "restore.queryFail" = "  Restauracion: no se pudo consultar System Restore."
        "restore.check" = "  Compruebe Proteccion del sistema en la unidad del sistema (sysdm.cpl > System Protection)."
        "applies.now" = "  Efecto: YA desde este menu (no hace falta el menu 8)."
        "applies.m8" = "  Efecto: despues del menu 8 (Apply Hardening)."
        "applies.pref" = "  Preferencia: guardada al instante."
        "applies.dns" = "  DNS de Windows: solo tras Apply - pulse A aqui, o menu 8 (seccion DNS on)."
        "input.tooManyN" = "  Demasiadas entradas no validas; se usa N."
        "input.yn" = "  Error de entrada. Escriba Y o N."
        "input.ynOnly" = "  No valido. Solo Y o N."
        "input.tooManyCancel" = "  Demasiadas entradas no validas; se cancela."
        "input.yesNo" = "  Error de entrada. Escriba YES para confirmar, o NO para cancelar."
        "input.yesOnly" = "  No valido. YES (mayusculas) para confirmar, o NO para cancelar."
        "input.menuNone" = "  Error interno: no hay opciones validas."
        "input.menuGiveUp" = "  Demasiadas entradas no validas; se cancela (0) si existe."
        "hdr.recovery" = "RECOVERY / FIX"
        "hdr.hardware" = "HARDWARE AND DRIVER GUIDANCE"
        "hdr.programs" = "PROGRAMS AND INSTALL PATHS"
        "hdr.sections" = "HARDENING SECTIONS"
        "hdr.dns" = "DNS RESOLVER"
        "hdr.browser" = "BROWSER PRIVACY POLICIES"
        "hdr.uninstall" = "UNINSTALL"
        "hdr.help" = "HELP AND REPORTS"
        "hdr.language" = "LANGUAGE"
        "rec.1" = "  1  Undo last Apply (tracked services, firewall groups, DNS snapshot, RDP prior)"
        "rec.2" = "  2  Services (Print Spooler, high-risk stack, Xbox)"
        "rec.3" = "  3  Network (remote access, LAN discovery, DNS DHCP / restore snapshot)"
        "rec.4" = "  4  Browser policies (per browser; Default reverts Bastion policies)"
        "rec.5" = "  5  Apps and UI (Copilot, Widgets/Suggestions, Game Bar)"
        "rec.6" = "  6  Security mitigations (StrictHandle, Defender, LSA, policies/tasks)"
        "rec.0" = "  0  Atras"
        "rec.notes" = "  Notas:"
        "rec.n1" = "Los hubs muestran primero el estado live, luego reverso / re-endurecer"
        "rec.n2" = "Reabrir rutas remotas/LAN o servicios aumenta la superficie de ataque"
        "rec.n3" = "El lastre Appx y OneDrive no se reinstalan aqui - System Restore o el fabricante"
        "rec.extra" = "Elija un hub concreto si sabe que se rompio. Full Undo (1) es mas amplio y sigue siendo best-effort."
        "lang.intro" = "  El manual y las capturas en operationlockedin.com siguen en ingles. Los numeros de menu no cambian."
        "lang.terms" = "  Dry Run, Apply, Recovery, StrictHandle y YES siguen en ingles en todos los idiomas."
        "lang.1" = "  1  English"
        "lang.2" = "  2  Deutsch"
        "lang.3" = "  3  Espanol"
        "lang.4" = "  4  Francais"
        "lang.0" = "  0  Atras"
        "lang.set" = "  Idioma establecido: {0}."
        "hw.noInstall" = "  Bastion NO instala controladores GPU ni flashea BIOS."
    }

    $fr = @{
        "menu.review" = "EXAMINER (aucun changement)"
        "menu.configure" = "CONFIGURER (enregistre les choix; Windows pas encore change)"
        "menu.execute" = "EXECUTER (modifie le systeme)"
        "menu.maintain" = "MAINTENIR (actions MAINTENANT)"
        "menu.safety" = "SECURITE (faites ceci d'abord)"
        "menu.system" = "SYSTEME"
        "menu.1" = "   1    Dry Run (apercu seulement)"
        "menu.2" = "   2    Security audit"
        "menu.3" = "   3    Guide materiel et pilotes"
        "menu.4" = "   4    Sections de durcissement"
        "menu.5" = "   5    Programmes et chemins d'installation"
        "menu.6" = "   6    Politiques de confidentialite navigateur (s'applique MAINTENANT)"
        "menu.D" = "   D    DNS resolver (preference; Apply via A dans D, ou 8)"
        "menu.7" = "   7    Quick Harden (preset guide + Apply)"
        "menu.8" = "   8    Apply Hardening (sections actives + file d'installation)"
        "menu.9" = "   9    Recovery / fix"
        "menu.10" = "  10    Desinstaller des programmes"
        "menu.13" = "  13    Creer / nommer un point de restauration"
        "menu.R" = "   R    Identique a 13 (raccourci)"
        "menu.11" = "  11    Aide et rapports"
        "menu.12" = "  12    Reinitialiser seulement la config Bastion"
        "menu.L" = "   L    Langue (les numeros restent; les captures du manuel sont en anglais)"
        "menu.0" = "   0    Quitter"
        "menu.select" = "  Choisir"
        "menu.flow" = "  Parcours: configurer (4/5/D) -> Dry Run (1) optionnel -> point 13 -> Apply (8)."
        "menu.exception6" = "  Exception: le menu 6 applique les politiques navigateur des que vous confirmez un mode."
        "menu.installs" = "  Installations: IDs catalogue seulement; hash winget impose. GPU/BIOS: option 3 est un guide."
        "menu.queued" = "  Programmes en file d'installation: {0}"
        "menu.none" = "Aucun"
        "status.dataDir" = "  Repertoire de donnees: {0}"
        "status.firstRun" = "  Premier lancement (ou store vide): valeurs par defaut. Aucune config Bastion anterieure."
        "status.loaded" = "  Config chargee depuis la session precedente."
        "status.defaults" = "  Config: valeurs en memoire (fichier absent ou illisible)."
        "status.lastApply" = "  Dernier Bastion Apply: {0} (v{1}){2}{3}"
        "status.noApply" = "  Aucun Apply enregistre (Dry Run / Apply utilisent la detection live de l'OS)."
        "status.browser" = "  Politiques navigateur: {0}"
        "status.dns" = "  DNS resolver:   {0}"
        "restore.ok" = "  Restauration: point recent OK ({0})"
        "restore.tip" = "  Conseil: creez quand meme un point frais avec 13 / R avant un Apply important."
        "restore.old" = "  Restauration: des points existent, aucun dans les 48 dernieres heures."
        "restore.oldAction" = "  Action: 13 ou R pour un point nomme avant Apply / Quick Harden."
        "restore.none" = "  Restauration: AUCUN point sur ce PC."
        "restore.noneAction" = "  Action: 13 ou R AVANT Apply, Quick Harden ou BloatApps."
        "restore.queryFail" = "  Restauration: impossible d'interroger System Restore."
        "restore.check" = "  Verifiez la Protection systeme du volume systeme (sysdm.cpl > System Protection)."
        "applies.now" = "  Effet: MAINTENANT depuis ce menu (pas besoin du menu 8)."
        "applies.m8" = "  Effet: apres le menu 8 (Apply Hardening)."
        "applies.pref" = "  Preference: enregistree tout de suite."
        "applies.dns" = "  DNS Windows: seulement apres Apply - A ici, ou menu 8 (section DNS on)."
        "input.tooManyN" = "  Trop d'entrees invalides; N par defaut."
        "input.yn" = "  Erreur de saisie. Entrez Y ou N."
        "input.ynOnly" = "  Invalide. Y ou N seulement."
        "input.tooManyCancel" = "  Trop d'entrees invalides; annulation."
        "input.yesNo" = "  Erreur de saisie. YES pour confirmer, NO pour annuler."
        "input.yesOnly" = "  Invalide. YES (majuscules) pour confirmer, ou NO pour annuler."
        "input.menuNone" = "  Erreur interne: aucun choix valide."
        "input.menuGiveUp" = "  Trop d'entrees invalides; annulation (0) si disponible."
        "hdr.recovery" = "RECOVERY / FIX"
        "hdr.hardware" = "HARDWARE AND DRIVER GUIDANCE"
        "hdr.programs" = "PROGRAMS AND INSTALL PATHS"
        "hdr.sections" = "HARDENING SECTIONS"
        "hdr.dns" = "DNS RESOLVER"
        "hdr.browser" = "BROWSER PRIVACY POLICIES"
        "hdr.uninstall" = "UNINSTALL"
        "hdr.help" = "HELP AND REPORTS"
        "hdr.language" = "LANGUAGE"
        "rec.1" = "  1  Undo last Apply (tracked services, firewall groups, DNS snapshot, RDP prior)"
        "rec.2" = "  2  Services (Print Spooler, high-risk stack, Xbox)"
        "rec.3" = "  3  Network (remote access, LAN discovery, DNS DHCP / restore snapshot)"
        "rec.4" = "  4  Browser policies (per browser; Default reverts Bastion policies)"
        "rec.5" = "  5  Apps and UI (Copilot, Widgets/Suggestions, Game Bar)"
        "rec.6" = "  6  Security mitigations (StrictHandle, Defender, LSA, policies/tasks)"
        "rec.0" = "  0  Retour"
        "rec.notes" = "  Notes:"
        "rec.n1" = "Les hubs montrent d'abord l'etat live, puis inverse / re-durcissement"
        "rec.n2" = "Rouvrir des chemins distant/LAN ou des services elargit la surface d'attaque"
        "rec.n3" = "Le lest Appx et OneDrive ne se reinstalle pas ici - System Restore ou l'editeur"
        "rec.extra" = "Choisissez un hub precis si vous savez ce qui est casse. Full Undo (1) est plus large et reste best-effort."
        "lang.intro" = "  Le manuel et les captures sur operationlockedin.com restent en anglais. Les numeros de menu ne changent pas."
        "lang.terms" = "  Dry Run, Apply, Recovery, StrictHandle et YES restent en anglais dans chaque langue."
        "lang.set" = "  Langue definie: {0}."
        "lang.1" = "  1  English"
        "lang.2" = "  2  Deutsch"
        "lang.3" = "  3  Espanol"
        "lang.4" = "  4  Francais"
        "lang.0" = "  0  Retour"
        "hw.noInstall" = "  Bastion n'installe PAS de pilotes GPU et ne flashe pas le BIOS."
    }

    switch ($Lang) {
        "de" { return $de }
        "es" { return $es }
        "fr" { return $fr }
        default { return $en }
    }
}

function BT {
    param(
        [Parameter(Mandatory)][string]$Key,
        [object[]]$FormatArgs
    )
    if ($null -eq $script:BastionTextEn) {
        $script:BastionTextEn = Get-BastionLocaleCatalog -Lang "en"
        $script:BastionText = $script:BastionTextEn
    }
    $s = $null
    if ($script:BastionText -and $script:BastionText.ContainsKey($Key)) {
        $s = [string]$script:BastionText[$Key]
    }
    if ([string]::IsNullOrWhiteSpace($s) -and $script:BastionTextEn.ContainsKey($Key)) {
        $s = [string]$script:BastionTextEn[$Key]
    }
    if ([string]::IsNullOrWhiteSpace($s)) { return $Key }
    if ($FormatArgs -and @($FormatArgs).Count -gt 0) {
        try { return ($s -f $FormatArgs) } catch { return $s }
    }
    return $s
}

function Set-BastionUiLanguage {
    param([string]$Lang)
    $id = ([string]$Lang).Trim().ToLowerInvariant()
    if ($id -notin @("en","de","es","fr")) { $id = "en" }
    $script:BastionUiLanguage = $id
    $script:BastionTextEn = Get-BastionLocaleCatalog -Lang "en"
    $script:BastionText = Get-BastionLocaleCatalog -Lang $id
}

function Initialize-BastionLocale {
    if (-not $script:BastionUiLanguageFromConfig) {
        try {
            $ui = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
            if ($ui -in @("de","es","fr")) { $script:BastionUiLanguage = $ui }
        } catch {}
    }
    Set-BastionUiLanguage -Lang $script:BastionUiLanguage
}

function Show-LanguageMenu {
    while ($true) {
        Clear-BastionScreen
        Write-Header (BT "hdr.language")
        Write-Host (BT "lang.intro") -ForegroundColor Yellow
        Write-Host (BT "lang.terms") -ForegroundColor DarkGray
        Write-Host ""
        Write-Host (BT "lang.1")
        Write-Host (BT "lang.2")
        Write-Host (BT "lang.3")
        Write-Host (BT "lang.4")
        Write-Host (BT "lang.0")
        $c = Read-MenuChoice -Prompt (BT "menu.select") -Valid @("0","1","2","3","4")
        switch ($c) {
            "0" { return }
            "1" { Set-BastionUiLanguage "en" }
            "2" { Set-BastionUiLanguage "de" }
            "3" { Set-BastionUiLanguage "es" }
            "4" { Set-BastionUiLanguage "fr" }
        }
        $script:BastionUiLanguageSaved = $true
        try { Save-BastionConfig } catch {}
        Write-Host (BT "lang.set" @($script:BastionUiLanguage)) -ForegroundColor Green
        Wait-ForKey
        return
    }
}
