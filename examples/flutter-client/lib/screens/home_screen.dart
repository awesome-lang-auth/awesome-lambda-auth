import 'package:awesome_flutter_auth/awesome_flutter_auth.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';

import '../config.dart';
import '../open_url.dart';

/// Profilo, sessioni e iscrizione TOTP.
///
/// Due chiamate qui sono avvolte in `try`, e non per prudenza generica: contro
/// questo stack il client spedito ci **lancia**, e sono difetti del client, non
/// del server. Entrambi sono della stessa famiglia del campo `sub` mancante
/// chiuso da awesome-go-auth#46 — un cast non-nullable su un campo che non
/// arriva non degrada un client, lo termina.
///
/// 1. `getActiveSessions()`: `SessionInfo.fromJson` legge `json['handle']`,
///    ma il contratto manda `sessionHandle` (wire-contract.md:236, e la
///    reference fa lo stesso). Il cast e' `as String`, non nullable.
///
/// 2. `setup2fa()`: `TotpSetupData.fromJson` fa `json['qrCode'] as String`,
///    e questo port non manda `qrCode` — e' una deviazione registrata, perche'
///    un encoder QR non sta ne' nella stdlib ne' in golang.org/x/crypto.
///    Il commento upstream dice «un client disegna da se' otpauthUrl», ma
///    questo client non ci arriva: muore prima, e `TotpSetupData` non espone
///    nemmeno `otpauthUrl`.
///
/// Il demo li mostra invece di morire, cosi' il difetto si vede.
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.auth, required this.user});

  final AuthClient auth;
  final AuthUser user;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<SessionInfo> _sessions = const [];
  String? _sessionsError;
  String? _totpSecret;
  String? _totpError;
  String? _notice;
  bool _busy = false;

  final _totpCode = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadSessions();
  }

  @override
  void dispose() {
    _totpCode.dispose();
    super.dispose();
  }

  Future<void> _loadSessions() async {
    try {
      final list = await widget.auth.getActiveSessions();
      if (!mounted) return;
      setState(() {
        _sessions = list;
        _sessionsError = null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _sessions = const [];
        _sessionsError =
            'Il client non riesce a leggere le sessioni: SessionInfo.fromJson '
            'cerca "handle" mentre il contratto manda "sessionHandle", e il '
            'cast non e\' nullable.\n\n$e';
      });
    }
  }

  Future<void> _startTotp() async {
    setState(() {
      _busy = true;
      _totpError = null;
    });
    try {
      final res = await widget.auth.setup2fa();
      if (!mounted) return;
      setState(() {
        _busy = false;
        if (res.success && res.data != null) {
          _totpSecret = res.data!.secret;
        } else {
          _totpError = res.error ?? 'Iscrizione non riuscita';
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _totpError =
            'Il client non riesce a leggere la risposta di /2fa/setup: '
            'TotpSetupData.fromJson pretende "qrCode", che questo port non '
            'manda (deviazione registrata), e il cast non e\' nullable.\n\n$e';
      });
    }
  }

  Future<void> _confirmTotp() async {
    setState(() => _busy = true);
    final res =
        await widget.auth.verify2faSetup(_totpCode.text.trim(), _totpSecret!);
    if (!mounted) return;
    setState(() {
      _busy = false;
      if (res.success) {
        _totpSecret = null;
        _totpCode.clear();
        _notice = 'TOTP attivato.';
      } else {
        _totpError = res.error ?? 'Codice non valido';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final user = widget.user;
    final small = Theme.of(context).textTheme.bodySmall;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Profilo'),
        actions: [
          IconButton(
            tooltip: 'Esci',
            onPressed: widget.auth.logout,
            icon: const Icon(Icons.logout),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Trasporto: ${DemoConfig.transport}', style: small),
                  const SizedBox(height: 12),
                  // `sub` in evidenza: e' il campo che mancava su uno stack
                  // vivo finche' non e' arrivata awesome-go-auth#46, e la sua
                  // assenza faceva terminare proprio questo client.
                  _field('sub', user.sub),
                  _field('email', user.email),
                  _field('email verificata', user.isEmailVerified ? 'si' : 'no'),
                  _field('2FA',
                      (user.isTotpEnabled ?? false) ? 'attivo' : 'non attivo'),
                ],
              ),
            ),
          ),
          // Il link compare solo sul web: su Android l'app *e'* gia' l'APK.
          if (DemoConfig.hasApk && kIsWeb) ...[
            const SizedBox(height: 16),
            Card(
              child: ListTile(
                leading: const Icon(Icons.android),
                title: const Text('Scarica l\'APK Android'),
                subtitle: Text(
                  'Stesso demo, stesso backend, trasporto bearer invece del '
                  'cookie. Serve consentire l\'installazione da origini '
                  'sconosciute.',
                  style: small,
                ),
                trailing: const Icon(Icons.download),
                onTap: () => openUrl(DemoConfig.apkUrl),
              ),
            ),
          ],
          const SizedBox(height: 16),
          _sessionsCard(small),
          const SizedBox(height: 16),
          _totpCard(small),
          if (_notice != null)
            Padding(
              padding: const EdgeInsets.only(top: 16),
              child: Text(_notice!),
            ),
        ],
      ),
    );
  }

  Widget _field(String label, String value) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              width: 140,
              child: Text(label, style: Theme.of(context).textTheme.bodySmall),
            ),
            Expanded(child: SelectableText(value)),
          ],
        ),
      );

  Widget _sessionsCard(TextStyle? small) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text('Sessioni attive',
                      style: Theme.of(context).textTheme.titleMedium),
                  IconButton(
                    onPressed: _loadSessions,
                    icon: const Icon(Icons.refresh),
                  ),
                ],
              ),
              if (_sessionsError != null)
                Text(_sessionsError!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error))
              else if (_sessions.isEmpty)
                Text('Nessuna sessione elencata.', style: small)
              else
                for (final s in _sessions)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: SelectableText(s.handle),
                  ),
            ],
          ),
        ),
      );

  Widget _totpCard(TextStyle? small) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Secondo fattore',
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              if ((widget.user.isTotpEnabled ?? false))
                Text('Il TOTP e\' attivo su questo account.', style: small)
              else if (_totpSecret == null)
                FilledButton(
                  onPressed: _busy ? null : _startTotp,
                  child: const Text('Attiva il TOTP'),
                )
              else ...[
                Text('Segreto da inserire nell\'app di autenticazione:',
                    style: small),
                const SizedBox(height: 6),
                SelectableText(_totpSecret!),
                const SizedBox(height: 12),
                TextField(
                  controller: _totpCode,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(labelText: 'Codice'),
                ),
                const SizedBox(height: 12),
                FilledButton(
                  onPressed: _busy ? null : _confirmTotp,
                  child: const Text('Conferma'),
                ),
              ],
              if (_totpError != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    _totpError!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                  ),
                ),
            ],
          ),
        ),
      );
}
