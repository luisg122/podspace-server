import { Response } from 'express';
import { body } from 'express-validator';

import AuthCode, { AuthCodeDocument } from '../models/AuthCode';
import User, { UserDocument } from '../models/User';
import { ApplicationRequest } from '../utils/ApplicationRequest';
import BaseRoute from '../utils/BaseRoute';
import { RouteMethod } from '../utils/constants';
import MiddlewareUtils from '../utils/MiddlewareUtils';
import RouteError from '../utils/RouteError';

type VerifyCodeBody = Pick<AuthCodeDocument, 'phoneNumber'> & {
  code: number;
};

type VerifyCodeRequest = ApplicationRequest<{}, VerifyCodeBody>;

export default class VerifyCodeRoute extends BaseRoute<boolean> {
  constructor() {
    super({
      method: RouteMethod.POST,
      path: '/verify'
    });
  }

  /**
   * Validate the following inputs:
   *  - body.code
   *  - body.phoneNumber
   */
  middleware() {
    return [
      body('code')
        .isInt()
        .withMessage('The OTP must be a number')
        .isLength({ max: 6, min: 6 })
        .withMessage('The OTP must be a 6-digit number.'),

      body('phoneNumber')
        .isMobilePhone('en-US')
        .withMessage('The phone number you inputted was not valid.')
        .custom((phoneNumber: string) => {
          return MiddlewareUtils.isFound(AuthCode, { phoneNumber });
        })
        .withMessage({
          message: 'Are you sure you received an authentication code?',
          statusCode: 404
        })
    ];
  }

  /**
   * Validates that the OTP code given matches the OTP code associated with
   * the given phone number. If the OTP code does not match, should throw a 401
   * error.
   *
   * If the code is correct, then we should generate new authentication tokens
   * for the user and store them on the response. Also, if a user didn't
   * previously exist, we should create one associated with the phone number
   * at this point.
   *
   * @throws {RouteError} - If the code does not match what is in DB.
   */
  async content(req: VerifyCodeRequest, res: Response): Promise<boolean> {
    const { code, phoneNumber } = req.body;

    // TODO: (8.04) Find the real code associated with the number from our
    // database.

    const authCode: AuthCodeDocument = await AuthCode.findOne({ phoneNumber });

    // TODO: (8.05) Compare the code we received in the request body with the
    // one from our database. If they differ, throw a RouteError and them know
    // what's wrong.

    if (authCode.value !== code) {
      throw new RouteError({
        message: 'Invalid code entered.',
        statusCode: 401
      });
    }

    // TODO: (8.06) First try to get the user by fetching them from DB. But, if
    // they don't already exist, then just create a new user.
    let user: UserDocument = await User.findOne({ phoneNumber });

    if (!user) {
      user = await User.create({ phoneNumber });
    }

    // Renew's the user's tokens and attaches these new tokens on the
    // Express response object to send back to the client.
    const { accessToken, refreshToken } = await user.renewToken();
    MiddlewareUtils.attachTokens(res, { accessToken, refreshToken });

    // TODO: (8.07) In the case that the user properly authenticates with the
    // code, we no longer want to store the authentication code
    // (it's short-lived), so we delete it!

    await AuthCode.deleteOne({ phoneNumber });

    return true;
  }
}
