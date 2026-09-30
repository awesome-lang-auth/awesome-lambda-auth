// Fissa due difetti del client Flutter ufficiale contro le forme che il
// contratto manda davvero.
//
// I casi asseriscono cio' che il client **fa oggi**, non cio' che dovrebbe:
// cosi' la suite resta un segnale per rotture nuove invece di portarsi dietro
// un rosso permanente che tutti imparano a ignorare. Quando le issue upstream
// si chiudono questi test falliscono, ed e' il punto — il fallimento dice di
// togliere i `try` da home_screen.dart e di aggiornare questo file.
//
// La forma dei payload non e' inventata: e' quella di `docs/spec/wire-contract.md`
// e quella osservata su uno stack vivo.
import 'package:awesome_flutter_auth/awesome_flutter_auth.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('awesome-node-auth-flutter#21 — SessionInfo legge la chiave sbagliata',
      () {
    // GET /sessions -> {"sessions":[{...}]}, e ogni elemento porta
    // `sessionHandle` (wire-contract.md:236; la reference definisce
    // SessionInfo con sessionHandle in src/models/session.model.ts).
    final fromTheWire = <String, dynamic>{
      'sessionHandle': 'ses_ae852735043ae641f308b16b03b6a12d',
      'userId': 'usr_f9236f312f403024a58d91004685028b',
      'createdAt': '2026-08-15T18:19:25.574355646Z',
      'expiresAt': '2026-08-22T18:19:25.574355646Z',
    };

    test('lancia sulla risposta reale, invece di degradare', () {
      // `handle: json['handle'] as String` con la chiave assente prende null,
      // e il cast non e' nullable.
      expect(() => SessionInfo.fromJson(fromTheWire), throwsA(isA<TypeError>()));
    });

    test('accetta solo la chiave che nessun server manda', () {
      final invented = <String, dynamic>{'handle': 'ses_x'};
      expect(SessionInfo.fromJson(invented).handle, 'ses_x');
    });
  });

  group('awesome-node-auth-flutter#22 — TotpSetupData pretende qrCode', () {
    // POST /2fa/setup su questo port -> {"secret":…,"otpauthUrl":…}.
    // `qrCode` e' assente per deviazione registrata: un encoder QR non sta ne'
    // nella stdlib ne' in golang.org/x/crypto, e il port Rust della famiglia
    // fa la stessa scelta. La reference lo manda, ma la sua stessa interfaccia
    // servita lo tratta come facoltativo (`if (setupData.qrCode)`).
    final fromTheWire = <String, dynamic>{
      'secret': 'FU4HO3DFPBGFMVKRLJ4WG4JSIEZG4WJVORDEKNTIGNZQ',
      'otpauthUrl':
          'otpauth://totp/demo@example.com?issuer=awesome-go-auth&secret=FU4HO3DFPBGFMVKRLJ4WG4JSIEZG4WJVORDEKNTIGNZQ',
    };

    test('lancia quando qrCode non arriva', () {
      expect(
        () => TotpSetupData.fromJson(fromTheWire),
        throwsA(isA<TypeError>()),
      );
    });

    test('otpauthUrl non e\' comunque raggiungibile attraverso il modello', () {
      // Anche rendendo qrCode nullable il client non potrebbe disegnare il QR:
      // TotpSetupData non ha un campo per il provisioning URI e fromJson non
      // lo legge. E' la seconda meta' della #22.
      final withQr = Map<String, dynamic>.from(fromTheWire)
        ..['qrCode'] = 'data:image/png;base64,iVBORw0KGgo=';
      final parsed = TotpSetupData.fromJson(withQr);

      expect(parsed.secret, fromTheWire['secret']);
      expect(parsed.qrCode, startsWith('data:image/png;base64,'));
      // Nessuna asserzione su otpauthUrl: il campo non esiste. Se un giorno
      // comparisse, questo test va esteso a pretenderlo.
    });
  });
}
