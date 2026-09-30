import 'package:awesome_flutter_auth/awesome_flutter_auth.dart';
import 'package:flutter/material.dart';

import 'config.dart';
import 'screens/home_screen.dart';
import 'screens/login_screen.dart';

void main() {
  runApp(const DemoApp());
}

class DemoApp extends StatefulWidget {
  const DemoApp({super.key});

  @override
  State<DemoApp> createState() => _DemoAppState();
}

class _DemoAppState extends State<DemoApp> {
  late final AuthClient auth;

  @override
  void initState() {
    super.initState();
    // `headless: true` perche' i redirect automatici della libreria puntano a
    // `window.location`, che su Android non esiste e su web scavalcherebbe il
    // Navigator. Qui la navigazione la decide l'app, reagendo allo stato.
    auth = AuthClient(
      AuthOptions(apiPrefix: DemoConfig.apiPrefix, headless: true),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'awesome-lambda-auth — demo Flutter',
      theme: ThemeData(colorSchemeSeed: const Color(0xFF2F5BD7)),
      darkTheme: ThemeData(
        colorSchemeSeed: const Color(0xFF2F5BD7),
        brightness: Brightness.dark,
      ),
      home: AuthGate(auth: auth),
    );
  }
}

/// Mostra il login o la schermata autenticata, seguendo lo stato della libreria.
class AuthGate extends StatelessWidget {
  const AuthGate({super.key, required this.auth});

  final AuthClient auth;

  @override
  Widget build(BuildContext context) {
    final misconfig = DemoConfig.misconfiguration;
    if (misconfig != null) {
      return Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Text(misconfig, textAlign: TextAlign.center),
          ),
        ),
      );
    }

    return StreamBuilder<AuthUser?>(
      stream: auth.state.userStream,
      builder: (context, snapshot) {
        if (!auth.state.isInitialized && !snapshot.hasData) {
          return const Scaffold(
            body: Center(child: CircularProgressIndicator()),
          );
        }
        final user = snapshot.data;
        return user == null
            ? LoginScreen(auth: auth)
            : HomeScreen(auth: auth, user: user);
      },
    );
  }
}
