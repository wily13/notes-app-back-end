const ClientError = require('../../exceptions/ClientError');

class AuthenticationsHandler {
  constructor(authenticationsService, usersService, tokenManager, validator) {
    this._authenticationsService = authenticationsService;
    this._usersService = usersService;
    this._tokenManager = tokenManager;
    this._validator = validator;

    this.postAuthenticationHandler = this.postAuthenticationHandler.bind(this);
    this.putAuthenticationHandler = this.putAuthenticationHandler.bind(this);
    this.deleteAuthenticationHandler = this.deleteAuthenticationHandler.bind(this);
  }

  async postAuthenticationHandler(request, h) {
    try {
      // TODO: validasi dulu payload menggunakan fungsi validatePostAuthenticationPayload
      //  melalui this._validator.
      this._validator.validatePostAuthenticationPayload(request.payload);

      // TODO: memeriksa kredensial yang ada pada request.payload,
      //  Gunakan this._usersService.verifyUserCredential untuk
      const { username, password } = request.payload;
      const id = await this._usersService.verifyUserCredential(username, password);

      // TODO: Membuat access token, gunakan fungsi this._tokenManager.generateAccessToken
      //  dan refresh token, gunakan this._tokenManager.generateRefreshToken
      const accessToken = this._tokenManager.generateAccessToken({ id });
      const refreshToken = this._tokenManager.generateRefreshToken({ id });

      // TODO: menyimpan refreshToken, gunakan fungsi this._authenticationsService.addRefreshToken
      await this._authenticationsService.addRefreshToken(refreshToken);

      // TODO: kita kembalikan request dengan respons yang membawa accessToken
      //  dan refreshToken di data body
      const response = h.response({
        status: 'success',
        message: 'Authentication berhasil ditambahkan',
        data: {
          accessToken,
          refreshToken,
        },
      });
      response.code(201);
      return response;
    } catch (error) {
      if (error instanceof ClientError) {
        const response = h.response({
          status: 'fail',
          message: error.message,
        });
        response.code(error.statusCode);
        return response;
      }

      // Server ERROR!
      const response = h.response({
        status: 'error',
        message: 'Maaf, terjadi kegagalan pada server kami.',
      });
      response.code(500);
      console.error(error);
      return response;
    }
  }

  async putAuthenticationHandler(request, h) {
    try {
      // TODO: validasi dulu payload menggunakan fungsi validatePostAuthenticationPayload
      //  melalui this._validator.
      this._validator.validatePutAuthenticationPayload(request.payload);

      // TODO: dapatkan nilai refreshToken pada request.payload
      //  dan verifikasi refreshToken baik dari sisi database maupun signature token.
      const { refreshToken } = request.payload;
      await this._authenticationsService.verifyRefreshToken(refreshToken);
      const { id } = this._tokenManager.verifyRefreshToken(refreshToken);

      // TODO: Setelah refreshToken lolos dari verifikasi database dan signature,
      //  sekarang kita bisa secara aman membuat accessToken baru
      //  dan melampirkannya sebagai data di body respons.
      const accessToken = this._tokenManager.generateAccessToken({ id });
      return {
        status: 'success',
        message: 'Access Token berhasil diperbarui',
        data: {
          accessToken,
        },
      };
    } catch (error) {
      if (error instanceof ClientError) {
        const response = h.response({
          status: 'fail',
          message: error.message,
        });
        response.code(error.statusCode);
        return response;
      }

      // Server ERROR!
      const response = h.response({
        status: 'error',
        message: 'Maaf, terjadi kegagalan pada server kami.',
      });
      response.code(500);
      console.error(error);
      return response;
    }
  }

  async deleteAuthenticationHandler(request, h) {
    try {
      // TODO: validasi dulu payload menggunakan fungsi validatePostAuthenticationPayload
      //  melalui this._validator.
      this._validator.validateDeleteAuthenticationPayload(request.payload);

      // TODO: memastikan refreshToken tersebut ada di database. Caranya,
      //  gunakan fungsi this._authenticationsService.verifyRefreshToken
      const { refreshToken } = request.payload;
      await this._authenticationsService.verifyRefreshToken(refreshToken);

      // TODO: Setelah proses verifikasi refreshToken selesai, menghapusnya dari database
      //  menggunakan fungsi this._authenticationsService.deleteRefreshToken
      await this._authenticationsService.verifyRefreshToken(refreshToken);
      await this._authenticationsService.deleteRefreshToken(refreshToken);

      // TODO: berikan respons yang sesuai skenario pengujian pada request ini
      return {
        status: 'success',
        message: 'Refresh token berhasil dihapus',
      };
    } catch (error) {
      if (error instanceof ClientError) {
        const response = h.response({
          status: 'fail',
          message: error.message,
        });
        response.code(error.statusCode);
        return response;
      }

      // Server ERROR!
      const response = h.response({
        status: 'error',
        message: 'Maaf, terjadi kegagalan pada server kami.',
      });
      response.code(500);
      console.error(error);
      return response;
    }
  }
}

module.exports = AuthenticationsHandler;
