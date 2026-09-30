// Fissa il comportamento corretto del client Flutter ufficiale contro le forme
// che il contratto manda davvero, per i due difetti che questo demo ha fatto
// emergere e che awesome_flutter_auth ha chiuso in 1.10.1.
//
// I casi asseriscono cio' che il client deve fare. Contro
// `awesome_node_auth_flutter` 1.10.0 falliscono tutti: `SessionInfo.fromJson`
// lanciava un `TypeError` sulla risposta reale, `TotpSetupData.fromJson`
// lanciava quando `qrCode` non arrivava, e `otpauthUrl` non esisteva nemmeno
// (il file non compilerebbe). Se uno di questi torna rosso, il difetto e'
// rientrato e il demo torna a morire su /sessions o su /2fa/setup.
//
// La forma dei payload non e' inventata: e' quella di `docs/spec/wire-contract.md`
// e quella osservata su uno stack vivo.
import 'package:awesome_flutter_auth/awesome_flutter_auth.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('awesome-flutter-auth#21 — SessionInfo legge sessionHandle', () {
    // GET /sessions -> {"sessions":[{...}]}, e ogni elemento porta
    // `sessionHandle` (wire-contract.md:236; la reference definisce
    // SessionInfo con sessionHandle in src/models/session.model.ts).
    final fromTheWire = <String, dynamic>{
      'sessionHandle': 'ses_ae852735043ae641f308b16b03b6a12d',
      'userId': 'usr_f9236f312f403024a58d91004685028b',
      'createdAt': '2026-08-15T18:19:25.574355646Z',
      'expiresAt': '2026-08-22T18:19:25.574355646Z',
    };

    test('legge la risposta reale', () {
      final parsed = SessionInfo.fromJson(fromTheWire);
      expect(parsed.handle, fromTheWire['sessionHandle']);
      expect(parsed.createdAt, isNotNull);
      // Questo stack non manda `isCurrent`.
      expect(parsed.isCurrent, isFalse);
    });

    test('senza handle lancia FormatException, non TypeError', () {
      // getActiveSessions() la intercetta e salta la voce invece di far
      // fallire tutta la lista.
      expect(
        () => SessionInfo.fromJson(<String, dynamic>{'userId': 'usr_x'}),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('awesome-flutter-auth#22 — TotpSetupData senza qrCode', () {
    // POST /2fa/setup su questo port -> {"secret":…,"otpauthUrl":…}.
    // `qrCode` e' assente per deviazione registrata: un encoder QR non sta ne'
    // nella stdlib ne' in golang.org/x/crypto, e il port Rust della famiglia
    // fa la stessa scelta.
    final fromTheWire = <String, dynamic>{
      'secret': 'FU4HO3DFPBGFMVKRLJ4WG4JSIEZG4WJVORDEKNTIGNZQ',
      'otpauthUrl':
          'otpauth://totp/demo@example.com?issuer=awesome-go-auth&secret=FU4HO3DFPBGFMVKRLJ4WG4JSIEZG4WJVORDEKNTIGNZQ',
    };

    test('legge la risposta reale, con qrCode null', () {
      final parsed = TotpSetupData.fromJson(fromTheWire);
      expect(parsed.secret, fromTheWire['secret']);
      expect(parsed.qrCode, isNull);
    });

    test('espone otpauthUrl, da cui un client disegna il QR', () {
      final parsed = TotpSetupData.fromJson(fromTheWire);
      expect(parsed.otpauthUrl, fromTheWire['otpauthUrl']);
    });

    test('senza secret lancia FormatException, non TypeError', () {
      // setup2fa() la trasforma in AuthResult.failure.
      expect(
        () => TotpSetupData.fromJson(<String, dynamic>{'otpauthUrl': 'x'}),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
