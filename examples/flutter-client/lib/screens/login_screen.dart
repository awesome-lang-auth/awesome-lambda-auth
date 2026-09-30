import 'package:awesome_flutter_auth/awesome_flutter_auth.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';

import '../config.dart';
import '../open_url.dart';
import 'register_screen.dart';

/// Login con la sfida di secondo fattore.
///
/// La sfida arriva come `LoginResult.requires2FA` con un `tempToken`: e' il
/// giro che upstream awesome-go-auth#42 aveva rotto, perche' il 403 non
/// portava il token e il client restava senza nulla da presentare.
class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key, required this.auth});

  final AuthClient auth;

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _totp = TextEditingController();

  bool _busy = false;
  String? _error;
  String? _tempToken;
  List<String> _methods = const [];

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    _totp.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final res = await widget.auth.login(_email.text.trim(), _password.text);
    if (!mounted) return;
    setState(() {
      _busy = false;
      if (res.requires2fa) {
        final token = res.tempToken;
        if (token == null) {
          _error = 'Il server chiede un secondo fattore ma non manda un '
              'tempToken: la sfida non e\' completabile.';
          return;
        }
        _tempToken = token;
        _methods = res.availableMethods;
        return;
      }
      if (!res.success) _error = res.error ?? 'Accesso non riuscito';
    });
  }

  Future<void> _verify() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    final res = await widget.auth.validate2fa(_tempToken!, _totp.text.trim());
    if (!mounted) return;
    setState(() {
      _busy = false;
      if (!res.success) _error = res.error ?? 'Codice non valido';
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('awesome-lambda-auth — demo Flutter')),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: _tempToken == null ? _credentials() : _challenge(),
          ),
        ),
      ),
    );
  }

  Widget _credentials() => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Accedi', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 6),
          Text(
            'Trasporto in uso: ${DemoConfig.transport}',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _email,
            keyboardType: TextInputType.emailAddress,
            decoration: const InputDecoration(labelText: 'Email'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _password,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Password'),
            onSubmitted: (_) => _busy ? null : _login(),
          ),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: _busy ? null : _login,
            child: Text(_busy ? 'Accesso…' : 'Accedi'),
          ),
          TextButton(
            onPressed: _busy
                ? null
                : () => Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => RegisterScreen(auth: widget.auth),
                      ),
                    ),
            child: const Text('Crea un account'),
          ),
          // Qui e non solo a sessione aperta: chi vuole provare il ramo bearer
          // deve poter prendere l'APK prima di autenticarsi, non dopo.
          if (DemoConfig.hasApk && kIsWeb) ...[
            const Divider(height: 32),
            Text(
              'Il ramo bearer si prova col build nativo: stesso demo, stesso '
              'backend, token al posto dei cookie.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: () => openUrl(DemoConfig.apkUrl),
              icon: const Icon(Icons.android),
              label: const Text('Scarica l\'APK Android'),
            ),
          ],
          _errorText(),
        ],
      );

  Widget _challenge() => Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text('Secondo fattore',
              style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 8),
          Text(
            _methods.isEmpty
                ? 'Questo account ha il secondo fattore attivo.'
                : 'Metodi disponibili: ${_methods.join(', ')}.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _totp,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(labelText: 'Codice TOTP'),
            onSubmitted: (_) => _busy ? null : _verify(),
          ),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: _busy ? null : _verify,
            child: Text(_busy ? 'Verifica…' : 'Verifica'),
          ),
          TextButton(
            onPressed: _busy
                ? null
                : () => setState(() {
                      _tempToken = null;
                      _methods = const [];
                      _totp.clear();
                      _error = null;
                    }),
            child: const Text('Annulla'),
          ),
          _errorText(),
        ],
      );

  Widget _errorText() {
    final error = _error;
    if (error == null) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(top: 16),
      child: Text(
        error,
        style: TextStyle(color: Theme.of(context).colorScheme.error),
      ),
    );
  }
}
