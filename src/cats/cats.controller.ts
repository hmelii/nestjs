import { Controller, Get, Req, Post, Redirect, Query, Param } from '@nestjs/common';
import { Request } from 'express';

@Controller('cats')
export class CatsController {
    @Get()
    findAll(@Req() request: Request): string { // получаем GET параметры из адресной строки Например http://localhost:3000/cats?test=100 -> { test: 100 }
        console.log(request.query)
        return `This action returns all cats`;
    }

    @Post()
    create(): string {
        return 'This action adds a new cat';
    }

    @Get('docs')
    @Redirect('https://docs.nestjs.com', 302)
    getDocs(@Query('version') version) { // маршрут типа http://localhost:3000/cats/docs или http://localhost:3000/cats/docs?version=5 идет редирект
        if (version && version === '5') {
            return { url: 'https://docs.nestjs.com/v5/' };
        }
    }

    /*
    @Get(':id')
    findOne(@Param() params): string { // маршрут типа http://localhost:3000/cats/1
        console.log(params.id);
        return `This action returns a #${params.id} cat`;
    }
    */

    @Get(':id')
    findOne(@Param('id') id): string { // второй способ
        return `This action returns a #${id} cat`;
    }


}
