import { HttpStatus, type ArgumentsHost } from '@nestjs/common';
import { MulterError } from 'multer';
import { MulterExceptionFilter } from './multer-exception.filter';

describe('MulterExceptionFilter', () => {
  const filter = new MulterExceptionFilter();

  function makeHost() {
    const json = jest.fn();
    const status = jest.fn().mockReturnValue({ json });
    return { status, json };
  }

  it('LIMIT_FILE_SIZE → 413', () => {
    const { status, json } = makeHost();
    const host = {
      switchToHttp: () => ({ getResponse: () => ({ status }) }),
    } as unknown as ArgumentsHost;
    filter.catch(new MulterError('LIMIT_FILE_SIZE', 'apk'), host);
    expect(status).toHaveBeenCalledWith(HttpStatus.PAYLOAD_TOO_LARGE);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ code: 'UPLOAD_ERROR' }));
  });

  it.each([
    ['LIMIT_FILE_COUNT', HttpStatus.BAD_REQUEST],
    ['LIMIT_UNEXPECTED_FILE', HttpStatus.BAD_REQUEST],
    ['LIMIT_FIELD_KEY', HttpStatus.BAD_REQUEST],
    ['LIMIT_FIELD_COUNT', HttpStatus.BAD_REQUEST],
    ['LIMIT_FIELD_SIZE', HttpStatus.BAD_REQUEST],
  ])('%s → %i', (code, expected) => {
    const { status } = makeHost();
    const host = {
      switchToHttp: () => ({ getResponse: () => ({ status }) }),
    } as unknown as ArgumentsHost;
    filter.catch(new MulterError(code as never, 'apk'), host);
    expect(status).toHaveBeenCalledWith(expected);
  });

  it('未知 code → 500 兜底', () => {
    const { status, json } = makeHost();
    const host = {
      switchToHttp: () => ({ getResponse: () => ({ status }) }),
    } as unknown as ArgumentsHost;
    filter.catch(new MulterError('SOMETHING_ELSE' as never), host);
    expect(status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ detail: 'SOMETHING_ELSE' }));
  });
});
