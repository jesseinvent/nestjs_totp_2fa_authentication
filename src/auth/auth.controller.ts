import { Body, Controller, ForbiddenException, Post } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { AuthService } from './auth.service';
import { Complet2FASetupDto } from './dto/complete_2fa_setup.dto';
import { Enable2FADto } from './dto/enable_2fa.dto';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UserService,
  ) {}

  @Post('signup')
  async signup(@Body() dto: SignupDto) {
    const user = await this.authService.signup(dto);
    return { user };
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('enable_2fa')
  async enable2fa(@Body() dto: Enable2FADto) {
    return this.authService.enable2faForUser(dto.email);
  }

  @Post('complete_2fa_setup')
  async complete2faSetup(@Body() dto: Complet2FASetupDto) {
    return this.authService.complete2FASetup(dto.email, dto.token);
  }
}
