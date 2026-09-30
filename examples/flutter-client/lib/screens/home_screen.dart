import 'package:awesome_flutter_auth/awesome_flutter_auth.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';

import '../config.dart';
import '../open_url.dart';

/// Profilo, sessioni e iscrizione TOTP.
///
/// Fino a `awesome_node_auth_flutter` 1.10.0 due chiamate qui lanciavano contro
/// questo stack (`SessionInfo` leggeva `handle` invece di `sessionHandle`,
/// `TotpSetupData` pretendeva `qrCode`), e il demo le avvolgeva in `try`.
/// Sono chiuse in 1.10.1 (awesome-flutter-auth#21 e #22) e i `try` non servono
/// piu': `test/client_defects_test.dart` fissa il comportamento corretto.
///
/// Questo port non manda `qrCode` (deviazione registrata), quindi l'iscrizione
/// mostra il segreto da inserire a mano e l'URI `otpauth://` che la libreria
/// ora espone.
class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.auth, required this.user});

  final AuthClient auth;
  final AuthUser user;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<SessionInfo> _sessions = const [];
  String? _totpSecret;
  String? _totpOtpauthUrl;
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
    final list = await widget.auth.getActiveSessions();
    if (!mounted) return;
    setState(() => _sessions = list);
  }

  Future<void> _startTotp() async {
    setState(() {
      _busy = true;
      _totpError = null;
    });
    final res = await widget.auth.setup2fa();
    if (!mounted) return;
    setState(() {
      _busy = false;
      if (res.success && res.data != null) {
        _totpSecret = res.data!.secret;
        _totpOtpauthUrl = res.data!.otpauthUrl;
      } else {
        _totpError = res.error ?? 'Iscrizione non riuscita';
      }
    });
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
        _totpOtpauthUrl = null;
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
              if (_sessions.isEmpty)
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
                // Il port non manda `qrCode`: l'URI di provisioning si incolla
                // in un'app di autenticazione o in un generatore di QR.
                if (_totpOtpauthUrl != null) ...[
                  const SizedBox(height: 12),
                  Text('URI di provisioning:', style: small),
                  const SizedBox(height: 6),
                  SelectableText(_totpOtpauthUrl!),
                ],
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
