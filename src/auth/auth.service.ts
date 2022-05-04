import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { SignupDto } from './dto/signup.dto';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import * as speakeasy from 'speakeasy';

@Injectable()
export class AuthService {
  constructor(private userService: UserService) {}
  async signup(dto: SignupDto) {
    const secret = this.generateSecret();

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(dto.password, salt);
    const user = await this.userService.create({
      full_name: dto.full_name,
      email: dto.email,
      password: hash,
      secret: secret.base32,
    });
    return user;
  }

  async login(dto: LoginDto) {
    const user = await this.userService.findByEmail(dto.email);

    if (!user) throw new UnauthorizedException('Invalid Credentails');

    const passwordMatches = await bcrypt.compare(dto.password, user.password);

    if (!passwordMatches)
      throw new UnauthorizedException('Invalid Credentails');

    return user;
  }

  async enable2faForUser(email: string) {
    const user = await this.userService.findByEmail(email);

    if (!user) {
      throw new ForbiddenException('User does not exists');
    }

    const secret = this.generateSecret();

    await this.userService.update(email, { twoFA_secret: secret.base32 });

    return { key: secret.base32 };
  }

  generateSecret() {
    const secret = speakeasy.generateSecret();

    console.log(secret);

    const { hex, base32 } = secret;

    return { hex, base32 };
  }

  async complete2FASetup(email: string, token: string) {
    const user = await this.userService.findByEmail(email);

    if (!user) {
      throw new ForbiddenException('User does not exists');
    }

    const verify2FAToken = this.verify2FAOtp(user.twoFA_secret, token);

    if (!verify2FAToken) {
      throw new BadRequestException('Invalid token provided');
    }

    await this.userService.update(email, { twoFA_enabled: true });

    return {
      status: true,
      message: '2FA enable for on account account',
    };
  }

  verify2FAOtp(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
    });
  }
}
