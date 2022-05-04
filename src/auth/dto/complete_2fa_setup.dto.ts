import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class Complet2FASetupDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  token: string;
}
