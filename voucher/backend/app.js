const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
app.use(bodyParser.json());
app.use(cors());


const sequelize = new Sequelize('toko_app', 'root', '', {
  host: 'localhost',
  dialect: 'mysql',
});


const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

const Voucher = sequelize.define('Voucher', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  code: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  expirationDate: {
    type: DataTypes.DATE,
    allowNull: false,
  },
});

User.hasMany(Voucher);
Voucher.belongsTo(User);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan saat mendaftar' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ where: { email: req.body.email } });
    if (!user) {
      return res.status(404).json({ error: 'Email tidak ditemukan' });
    }

    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validPassword) {
      return res.status(401).json({ error: 'Password salah' });
    }

    const accessToken = jwt.sign({ id: user.id }, 'secret_key');
    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan saat login' });
  }
});

app.get('/vouchers', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    const vouchers = await user.getVouchers();
    res.json(vouchers);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan saat mengambil data' });
  }
});

app.post('/generate-voucher', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User tidak ditemukan' });
    }

    const totalTransaction = 2000000;
    const voucherAmount = Math.floor(totalTransaction / 2000000) * 10000;

    const expirationDate = new Date();
    expirationDate.setMonth(expirationDate.getMonth() + 3); 
    const voucher = await Voucher.create({
      code: generateUniqueVoucherCode(), 
      expirationDate,
      UserId: user.id,
    });

    res.json({ voucherAmount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan saat membuat voucher' });
  }
});

app.post('/use-voucher', authenticateToken, async (req, res) => {
  try {
    const { voucherCode } = req.body;
    const user = await User.findByPk(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User tidak ditemukan' });
    }

    const voucher = await Voucher.findOne({
      where: {
        code: voucherCode,
        UserId: user.id,
      },
    });

    if (!voucher) {
      return res.status(404).json({ error: 'Voucher tidak valid untuk user ini' });
    }

    const currentDate = new Date();
    if (voucher.expirationDate < currentDate) {
      return res.status(400).json({ error: 'Voucher sudah kadaluarsa' });
    }

    await voucher.destroy();

    res.json({ message: 'Voucher berhasil digunakan' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Terjadi kesalahan saat menggunakan voucher' });
  }
});


app.listen(3001, () => {
  console.log('Server berjalan di http://localhost:3001');
});
