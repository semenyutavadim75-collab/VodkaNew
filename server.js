const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL подключение (Render даёт DATABASE_URL)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Сессии с хранением в PostgreSQL (не теряются при перезагрузке)
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'user_sessions',
        createTableIfMissing: true
    }),
    secret: 'vodka-client-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 дней
        httpOnly: true
    }
}));

// Инициализация таблиц
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                uid SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) DEFAULT NULL,
                hwid VARCHAR(255) DEFAULT NULL,
                subscription_type VARCHAR(50) DEFAULT NULL,
                subscription_expires TIMESTAMP DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Добавляем колонку email если её нет
        await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255) DEFAULT NULL`).catch(() => {});
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS keys (
                id SERIAL PRIMARY KEY,
                key_code VARCHAR(255) UNIQUE NOT NULL,
                subscription_type VARCHAR(50) NOT NULL,
                duration_days INTEGER NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                used_by INTEGER DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP DEFAULT NULL
            )
        `);
        
        console.log('✅ Таблицы PostgreSQL созданы');
    } catch (err) {
        console.error('❌ Ошибка создания таблиц:', err);
    }
}

initDB();

// API: Регистрация
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) return res.status(400).json({ success: false, message: 'Заполните все поля' });
    if (username.length < 3) return res.status(400).json({ success: false, message: 'Логин минимум 3 символа' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Пароль минимум 6 символов' });
    if (!email.includes('@')) return res.status(400).json({ success: false, message: 'Некорректный email' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING uid',
            [username, hashedPassword, email]
        );
        
        req.session.userId = result.rows[0].uid;
        req.session.username = username;
        res.json({ success: true, message: 'Регистрация успешна!', uid: result.rows[0].uid, username });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ success: false, message: 'Пользователь уже существует' });
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Заполните все поля' });

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(400).json({ success: false, message: 'Неверный логин или пароль' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ success: false, message: 'Неверный логин или пароль' });

        req.session.userId = user.uid;
        req.session.username = user.username;
        res.json({ success: true, message: 'Вход выполнен!', uid: user.uid, username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Проверка авторизации
app.get('/api/check-auth', async (req, res) => {
    if (!req.session.userId) return res.json({ authenticated: false });

    try {
        const result = await pool.query(
            'SELECT uid, username, email, hwid, created_at, subscription_type, subscription_expires FROM users WHERE uid = $1',
            [req.session.userId]
        );
        
        if (result.rows.length === 0) return res.json({ authenticated: false });
        const user = result.rows[0];

        let isActive = false;
        if (user.subscription_type) {
            if (user.subscription_type === 'lifetime') isActive = true;
            else if (user.subscription_expires) isActive = new Date(user.subscription_expires) > new Date();
        }

        res.json({
            authenticated: true,
            uid: user.uid,
            username: user.username,
            email: user.email,
            hwid: user.hwid,
            created_at: user.created_at,
            subscription_type: user.subscription_type,
            subscription_expires: user.subscription_expires,
            subscription_active: isActive
        });
    } catch (err) {
        console.error(err);
        res.json({ authenticated: false });
    }
});

// API: Выход
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Выход выполнен' });
});

// API: Смена пароля
app.post('/api/change-password', async (req, res) => {
    const { old_password, new_password } = req.body;
    const userId = req.session.userId;
    
    if (!userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    if (!old_password || !new_password) return res.status(400).json({ success: false, message: 'Заполните все поля' });
    if (new_password.length < 6) return res.status(400).json({ success: false, message: 'Новый пароль минимум 6 символов' });

    try {
        const result = await pool.query('SELECT password FROM users WHERE uid = $1', [userId]);
        if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Пользователь не найден' });

        const validPassword = await bcrypt.compare(old_password, result.rows[0].password);
        if (!validPassword) return res.status(400).json({ success: false, message: 'Неверный текущий пароль' });

        const hashedPassword = await bcrypt.hash(new_password, 10);
        await pool.query('UPDATE users SET password = $1 WHERE uid = $2', [hashedPassword, userId]);

        res.json({ success: true, message: 'Пароль успешно изменен!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Админ - все пользователи
app.get('/api/admin/users', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT uid, username, hwid, created_at, subscription_type, subscription_expires FROM users ORDER BY uid'
        );
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Удаление пользователя
app.post('/api/admin/delete-user', async (req, res) => {
    const { uid } = req.body;
    try {
        await pool.query('DELETE FROM users WHERE uid = $1', [uid]);
        res.json({ success: true, message: 'Пользователь удален' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Генерация ключа
app.post('/api/admin/generate-key', async (req, res) => {
    const { subscription_type, duration_days } = req.body;
    const keyCode = 'VDK-' + Math.random().toString(36).substring(2, 10).toUpperCase() + '-' + Math.random().toString(36).substring(2, 10).toUpperCase();

    try {
        await pool.query(
            'INSERT INTO keys (key_code, subscription_type, duration_days) VALUES ($1, $2, $3)',
            [keyCode, subscription_type, duration_days]
        );
        res.json({ success: true, key: keyCode });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Все ключи
app.get('/api/admin/keys', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM keys ORDER BY id DESC');
        res.json({ success: true, keys: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Активация ключа
app.post('/api/activate-key', async (req, res) => {
    const { key_code } = req.body;
    const userId = req.session.userId;
    if (!userId) return res.status(401).json({ success: false, message: 'Не авторизован' });
    if (!key_code) return res.status(400).json({ success: false, message: 'Введите ключ' });

    try {
        const keyResult = await pool.query('SELECT * FROM keys WHERE key_code = $1', [key_code]);
        if (keyResult.rows.length === 0) return res.status(400).json({ success: false, message: 'Ключ не найден' });
        
        const key = keyResult.rows[0];
        if (key.used) return res.status(400).json({ success: false, message: 'Ключ уже использован' });

        // Если это ключ сброса HWID
        if (key.subscription_type === 'hwid_reset') {
            await pool.query('UPDATE users SET hwid = NULL WHERE uid = $1', [userId]);
            await pool.query(
                'UPDATE keys SET used = TRUE, used_by = $1, used_at = CURRENT_TIMESTAMP WHERE key_code = $2',
                [userId, key_code]
            );
            return res.json({ success: true, message: 'HWID успешно сброшен! Теперь можете войти с другого ПК.' });
        }

        let expiresDate;
        if (key.subscription_type === 'lifetime') {
            const now = new Date();
            now.setFullYear(now.getFullYear() + 1337);
            expiresDate = now.toISOString();
        } else {
            // Проверяем текущую подписку и продлеваем если активна
            const userResult = await pool.query('SELECT subscription_expires FROM users WHERE uid = $1', [userId]);
            const user = userResult.rows[0];
            let startDate = new Date();
            
            if (user.subscription_expires && new Date(user.subscription_expires) > new Date()) {
                startDate = new Date(user.subscription_expires);
            }
            
            startDate.setDate(startDate.getDate() + key.duration_days);
            expiresDate = startDate.toISOString();
        }

        await pool.query(
            'UPDATE users SET subscription_type = $1, subscription_expires = $2 WHERE uid = $3',
            [key.subscription_type, expiresDate, userId]
        );
        
        await pool.query(
            'UPDATE keys SET used = TRUE, used_by = $1, used_at = CURRENT_TIMESTAMP WHERE key_code = $2',
            [userId, key_code]
        );

        res.json({ success: true, message: 'Подписка активирована!', subscription_type: key.subscription_type, expires: expiresDate });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка активации' });
    }
});


// ========================================
// API ДЛЯ ЛОАДЕРА
// ========================================

app.post('/api/launcher/check-subscription', async (req, res) => {
    const { username, password, hwid } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Введите логин и пароль', has_subscription: false });
    }
    if (!hwid) {
        return res.status(400).json({ success: false, message: 'HWID не передан', has_subscription: false });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Неверный логин или пароль', has_subscription: false });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, message: 'Неверный логин или пароль', has_subscription: false });
        }

        // HWID логика
        if (!user.hwid) {
            await pool.query('UPDATE users SET hwid = $1 WHERE uid = $2', [hwid, user.uid]);
            console.log(`✅ HWID записан для ${username}: ${hwid}`);
        } else if (user.hwid !== hwid) {
            return res.status(403).json({ success: false, message: 'Аккаунт привязан к другому ПК', has_subscription: false });
        }

        // Проверка подписки
        let hasSubscription = false;
        let subscriptionInfo = { type: user.subscription_type, expires: user.subscription_expires, active: false };

        if (user.subscription_type) {
            if (user.subscription_type === 'lifetime') {
                hasSubscription = true;
                subscriptionInfo.active = true;
            } else if (user.subscription_expires) {
                hasSubscription = new Date(user.subscription_expires) > new Date();
                subscriptionInfo.active = hasSubscription;
            }
        }

        res.json({
            success: true,
            message: hasSubscription ? 'Подписка активна' : 'Подписка отсутствует или истекла',
            has_subscription: hasSubscription,
            hwid: user.hwid || hwid,
            user: { uid: user.uid, username: user.username, created_at: user.created_at },
            subscription: subscriptionInfo
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера', has_subscription: false });
    }
});

app.get('/api/launcher/check-uid/:uid', async (req, res) => {
    const { uid } = req.params;
    
    try {
        const result = await pool.query(
            'SELECT uid, username, subscription_type, subscription_expires FROM users WHERE uid = $1',
            [uid]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Пользователь не найден', has_subscription: false });
        }

        const user = result.rows[0];
        let hasSubscription = false;
        
        if (user.subscription_type) {
            if (user.subscription_type === 'lifetime') hasSubscription = true;
            else if (user.subscription_expires) hasSubscription = new Date(user.subscription_expires) > new Date();
        }

        res.json({
            success: true,
            has_subscription: hasSubscription,
            user: { uid: user.uid, username: user.username },
            subscription: { type: user.subscription_type, expires: user.subscription_expires, active: hasSubscription }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера', has_subscription: false });
    }
});

// API: Сброс HWID пользователя (админ)
app.post('/api/admin/reset-hwid', async (req, res) => {
    const { uid } = req.body;
    try {
        await pool.query('UPDATE users SET hwid = NULL WHERE uid = $1', [uid]);
        res.json({ success: true, message: 'HWID сброшен' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
});

// API: Сброс базы данных (ОПАСНО!)
app.post('/api/admin/reset-database', async (req, res) => {
    const { confirm_password } = req.body;
    const ADMIN_PASSWORD = 'irairairA1';
    
    if (confirm_password !== ADMIN_PASSWORD) {
        return res.status(403).json({ success: false, message: 'Неверный пароль подтверждения' });
    }
    
    try {
        // Удаляем все данные
        await pool.query('DELETE FROM keys');
        await pool.query('DELETE FROM users');
        
        // Сбрасываем счётчик UID на 1
        await pool.query('ALTER SEQUENCE users_uid_seq RESTART WITH 1');
        await pool.query('ALTER SEQUENCE keys_id_seq RESTART WITH 1');
        
        console.log('⚠️ БАЗА ДАННЫХ ПОЛНОСТЬЮ ОЧИЩЕНА!');
        res.json({ success: true, message: 'База данных очищена' });
    } catch (err) {
        console.error('Ошибка сброса БД:', err);
        res.status(500).json({ success: false, message: 'Ошибка сброса базы данных' });
    }
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
