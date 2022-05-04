import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User {
  @Prop({ required: true })
  full_name: string;

  @Prop({ required: true, unique: true, type: String })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop()
  twoFA_secret: string;

  @Prop({ default: false })
  twoFA_enabled: boolean;
}
export type UserDocument = User & Document;

export const UserSchema = SchemaFactory.createForClass(User);
