import { IsEmail, IsNotEmpty } from 'class-validator';

export class Enable2FADto {
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
