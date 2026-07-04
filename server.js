const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(express.json());

app.use(express.static(__dirname));

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

// ==========================================
// RUTAS DE AUTENTICACIÓN Y USUARIOS
// ==========================================

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

// Obtener todos los usuarios (Solo Admin)
app.get('/api/usuarios', verificarToken, exigirRoles(['ADMINISTRADOR']), async (req, res) => {
  try {
    const query = `
      SELECT u.id_usuario, u.username, u.activo,
             COALESCE(array_agg(r.nombre) FILTER (WHERE r.nombre IS NOT NULL), '{}') AS roles
      FROM usuario u
      LEFT JOIN usuario_rol ur ON u.id_usuario = ur.id_usuario
      LEFT JOIN rol r ON ur.id_rol = r.id_rol
      GROUP BY u.id_usuario ORDER BY u.username ASC;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener usuarios.' });
  }
});

// Crear usuario (Solo Admin)
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
    res.status(201).json({ mensaje: `Usuario ${username} creado con éxito.` });
  } catch (err) {
    res.status(500).json({ error: 'El usuario ya existe o los datos son inválidos.' });
  }
});

// ==========================================
// RUTAS DEL SISTEMA GANADERO
// ==========================================

// Obtener resumen de estadísticas e información auxiliar para formularios
app.get('/api/ganado/resumen', verificarToken, async (req, res) => {
  try {
    const totalResult = await pool.query("SELECT COUNT(*) FROM animal WHERE activo = true");
    const ordenoResult = await pool.query("SELECT COUNT(*) FROM animal WHERE ordeno = true AND activo = true");
    const produccionResult = await pool.query("SELECT COALESCE(SUM(cantidad), 0) as total FROM produccion WHERE fecha = CURRENT_DATE");
    const tratamientosResult = await pool.query("SELECT COUNT(DISTINCT id_animal) FROM tratamiento WHERE fecha_aplicacion >= CURRENT_DATE - INTERVAL '3 days'");

    const origenes = await pool.query("SELECT * FROM origen");
    const ubicaciones = await pool.query("SELECT * FROM ubicacion");
    const colores = await pool.query("SELECT * FROM color");
    const razas = await pool.query("SELECT * FROM raza");
    const propietarios = await pool.query("SELECT * FROM propietario");
    const madres = await pool.query("SELECT id_animal, nombre FROM animal WHERE sexo = 'H' AND activo = true");
    const padres = await pool.query("SELECT id_animal, nombre FROM animal WHERE sexo = 'M' AND activo = true");

    res.json({
      kpis: {
        total_cabezas: totalResult.rows[0].count,
        vacas_ordeno: ordenoResult.rows[0].count,
        produccion_diaria: produccionResult.rows[0].total,
        tratamientos_activos: tratamientosResult.rows[0].count
      },
      catalogos: {
        origenes: origenes.rows,
        ubicaciones: ubicaciones.rows,
        colores: colores.rows,
        razas: razas.rows,
        propietarios: propietarios.rows,
        madres: madres.rows,
        padres: padres.rows
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al compilar el resumen estadístico.' });
  }
});

// Obtener lista completa de animales
app.get('/api/ganado/animales', verificarToken, async (req, res) => {
  try {
    const query = `
      SELECT a.*, u.nombre as ubicacion, o.nombre as origen,
             (SELECT nombre FROM animal WHERE id_animal = a.id_madre) as madre,
             (SELECT nombre FROM animal WHERE id_animal = a.id_padre) as padre
      FROM animal a
      JOIN ubicacion u ON a.id_ubicacion = u.id_ubicacion
      JOIN origen o ON a.id_origen = o.id_origen
      WHERE a.activo = true ORDER BY a.id_animal DESC;
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener inventario de animales.' });
  }
});

// Registrar nuevo animal
app.post('/api/ganado/animales', verificarToken, exigirRoles(['ADMINISTRADOR', 'DIGITADOR']), async (req, res) => {
  const { nombre, descripcion, sexo, fecha_nacimiento, id_madre, id_padre, id_origen, peso, ordeno, id_ubicacion, id_raza, id_color, id_propietario } = req.body;
  try {
    await pool.query('BEGIN');
    
    const insertAnimal = `
      INSERT INTO animal (nombre, descripcion, sexo, fecha_nacimiento, id_madre, id_padre, id_origen, peso, ordeno, id_ubicacion)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id_animal;
    `;
    const resAnimal = await pool.query(insertAnimal, [nombre, descripcion, sexo, fecha_nacimiento || null, id_madre || null, id_padre || null, id_origen, peso || 0, ordeno || false, id_ubicacion]);
    const idAnimal = resAnimal.rows[0].id_animal;

    if (id_color) await pool.query('INSERT INTO animal_color (id_animal, id_color) VALUES ($1, $2)', [idAnimal, id_color]);
    if (id_raza) await pool.query('INSERT INTO animal_raza (id_animal, id_raza) VALUES ($1, $2)', [idAnimal, id_raza]);
    if (id_propietario) await pool.query('INSERT INTO animal_propietario (id_animal, id_propietario) VALUES ($1, $2)', [idAnimal, id_propietario]);

    await pool.query('COMMIT');
    res.status(201).json({ mensaje: `Animal ${nombre} registrado con ID ${idAnimal}` });
  } catch (err) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: 'Error al insertar registro del animal.' });
  }
});

// Registrar un Nacimiento (Parto)
app.post('/api/ganado/partos', verificarToken, exigirRoles(['ADMINISTRADOR', 'DIGITADOR']), async (req, res) => {
  const { id_madre, fecha, observaciones, nombre_cria, sexo_cria, id_origen, id_ubicacion } = req.body;
  try {
    await pool.query('BEGIN');
    
    // 1. Guardar evento del parto
    await pool.query('INSERT INTO parto (id_madre, fecha, observaciones) VALUES ($1, $2, $3)', [id_madre, fecha, observaciones]);
    
    // 2. Insertar automáticamente la cría en la tabla animal si se provee nombre
    if (nombre_cria) {
      const insertCria = `
        INSERT INTO animal (nombre, sexo, fecha_nacimiento, id_madre, id_origen, id_ubicacion, descripcion)
        VALUES ($1, $2, $3, $4, $5, $6, $7);
      `;
      await pool.query(insertCria, [nombre_cria, sexo_cria, fecha, id_madre, id_origen, id_ubicacion, 'Cría nacida en hacienda']);
    }

    await pool.query('COMMIT');
    res.status(201).json({ mensaje: 'Parto y cría guardados con éxito.' });
  } catch (err) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: 'Error al procesar el nacimiento.' });
  }
});

// Registrar Producción Diaria de Leche
app.post('/api/ganado/produccion', verificarToken, exigirRoles(['ADMINISTRADOR', 'DIGITADOR']), async (req, res) => {
  const { id_animal, fecha, cantidad } = req.body;
  try {
    await pool.query('INSERT INTO produccion (id_animal, fecha, cantidad) VALUES ($1, $2, $3)', [id_animal, fecha, cantidad]);
    res.status(201).json({ mensaje: 'Registro de producción de leche añadido.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al insertar pesaje de leche.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
