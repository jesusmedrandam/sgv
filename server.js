const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(express.json());

// CONFIGURACIÓN PARA SERVIR LA WEB DESDE RENDER
// Sirve cualquier archivo HTML/JS en la raíz (como dashboard.html)
app.use(express.static(__dirname));

// Envía el login automáticamente al entrar a la URL principal
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

const JWT_SECRET = process.env.JWT_SECRET;

// MIDDLEWARES DE SEGURIDAD
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ error: 'Token no proporcionado.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado.' });
  }
};

const exigirRoles = (rolesPermitidos) => {
  return (req, res, next) => {
    const tienePermiso = req.usuario.roles.some(rol => rolesPermitidos.includes(rol));
    if (!tienePermiso) {
      return res.status(403).json({ error: 'No tienes los permisos necesarios.' });
    }
    next();
  };
};

// RUTA DE LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = `
      SELECT u.id_usuario, u.username, u.password, u.activo,
             COALESCE(array_agg(r.nombre) FILTER (WHERE r.nombre IS NOT NULL), '{}') AS roles
      FROM usuario u
      LEFT JOIN usuario_rol ur ON u.id_usuario = ur.id_usuario
      LEFT JOIN rol r ON ur.id_rol = r.id_rol
      WHERE u.username = $1
      GROUP BY u.id_usuario;
    `;
    const result = await pool.query(query, [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas.' });

    const usuario = result.rows[0];
    if (!usuario.activo) return res.status(403).json({ error: 'Usuario deshabilitado.' });

    const passwordValido = await bcrypt.compare(password, usuario.password);
    if (!passwordValido) return res.status(401).json({ error: 'Credenciales incorrectas.' });

    const token = jwt.sign(
      { id: usuario.id_usuario, username: usuario.username, roles: usuario.roles },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, usuario: { username: usuario.username, roles: usuario.roles } });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor.' });
  }
});

// RUTA PARA CREAR USUARIOS (Solo Admin)
app.post('/api/usuarios', verificarToken, exigirRoles(['ADMINISTRADOR']), async (req, res) => {
  const { username, password, rolesIds } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const nuevoUsuario = await pool.query(
      'INSERT INTO usuario (username, password) VALUES ($1, $2) RETURNING id_usuario',
      [username, passwordHash]
    );
    const idUsuario = nuevoUsuario.rows[0].id_usuario;

    if (rolesIds && rolesIds.length > 0) {
      for (const idRol of rolesIds) {
        await pool.query('INSERT INTO usuario_rol (id_usuario, id_rol) VALUES ($1, $2)', [idUsuario, idRol]);
      }
    }
    res.status(201).json({ mensaje: `Usuario ${username} creado.` });
  } catch (err) {
    res.status(500).json({ error: 'Error al crear usuario.' });
  }
});

// START
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
