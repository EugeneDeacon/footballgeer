// server.js

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const authenticateToken = require('./routes/auth');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// PostgreSQL подключение
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

const JWT_SECRET = process.env.JWT_SECRET;

// ✅ Middleware: проверка на админа
function isAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
}

// 🔐 Регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const query = 'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *';
        const values = [name, email, hashedPassword, 'user'];
        const { rows } = await pool.query(query, values);

        res.json({ message: 'Пользователь успешно зарегистрирован', user: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// 🔓 Логин
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (user.rows.length === 0) {
            return res.status(400).json({ error: 'Пользователь не найден' });
        }

        const userRow = user.rows[0];
        const isPasswordValid = await bcrypt.compare(password, userRow.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Неверный пароль' });
        }

        const token = jwt.sign(
            { id: userRow.id, role: userRow.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            message: 'Вход выполнен успешно',
            token,
            user: {
                id: userRow.id,
                name: userRow.name,
                email: userRow.email,
                role: userRow.role
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// 📦 Получить все товары
app.get('/api/products', async (req, res) => {
    try {
        const query = 'SELECT * FROM products';
        const { rows } = await pool.query(query);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ➕ Добавить товар (админ)
app.post('/api/products', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, category, price, image, description, popular } = req.body;
        const query = `
            INSERT INTO products (name, category, price, image, description, popular)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        `;
        const values = [name, category, price, image, description, popular];
        const { rows } = await pool.query(query, values);

        res.json({ message: 'Товар добавлен', product: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// 🛠 Обновить товар (админ)
app.put('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, category, price, image, description, popular } = req.body;

        const query = `
            UPDATE products
            SET name = $1, category = $2, price = $3, image = $4, description = $5, popular = $6
            WHERE id = $7
            RETURNING *
        `;
        const values = [name, category, price, image, description, popular, id];
        const { rows } = await pool.query(query, values);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }

        res.json({ message: 'Товар обновлен', product: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ❌ Удалить товар (админ)
app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const query = 'DELETE FROM products WHERE id = $1 RETURNING *';
        const { rows } = await pool.query(query, [id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }

        res.json({ message: 'Товар удалён', product: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// 👥 Получить всех пользователей (админ)
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM users');
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ✏️ Изменить роль пользователя (админ)
app.put('/api/users/:id/role', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;

        const query = 'UPDATE users SET role = $1 WHERE id = $2 RETURNING *';
        const { rows } = await pool.query(query, [role, id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        res.json({ message: 'Роль обновлена', user: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// 🚀 Старт сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});
