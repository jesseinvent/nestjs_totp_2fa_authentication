import { ForbiddenException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, MongooseError } from 'mongoose';
import { CreateUserDto } from './dto/createUser.dto';
import { User, UserDocument } from './schemas/user.schema';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async create(dto: CreateUserDto): Promise<User> {
    try {
      const user = await this.userModel.create(dto);
      console.log(user);

      return user;
    } catch (error: any) {
      if (error.code === 11000) {
        throw new ForbiddenException('Credentials taken');
      }
    }
  }

  async findByEmail(email: string): Promise<any> {
    return this.userModel.findOne({ email });
  }

  async update(email: string, body: object) {
    return this.userModel.findOneAndUpdate({ email }, body);
  }
}
