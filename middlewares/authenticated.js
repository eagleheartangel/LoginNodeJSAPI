'use strict';

const jwt = require('jwt-simple');
const moment = require('moment');
const secret = 'clave-secreta-para-generar-el-token-9999';

exports.authenticated = function (peticion, respuesta, siguiente) {
  // Comprobar si llega autorizacion
  if (!peticion.headers.authorization) {
    return respuesta.status(403).send({
      message: 'La peticion no tiene la cabecera de autorizacion',
    });
  }
  // Limpiar el token y quitar comillas
  const token = peticion.headers.authorization.replace(/['"]+/g, '');

  try {
    // Decodificar el token
    var payload = jwt.decode(token, secret);
    // Comprobar si el token ha expirado
    if (payload.exp <= moment.unix()) {
      return respuesta.status(404).send({
        message: 'El token ha expirado',
      });
    }
  } catch (ex) {
    return respuesta.status(404).send({
      message: 'El token no es valido',
    });
  }

  // Adjuntar usuario identificado a la peticion
  peticion.user = payload;
  // Pasar a la accion
  siguiente();
};
