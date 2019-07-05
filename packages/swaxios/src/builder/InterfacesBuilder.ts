/*
 * Wire
 * Copyright (C) 2019 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

import {Spec} from 'swagger-schema-official';
import {SwaxiosInterface} from '../definitions';
import {InterfaceGenerator} from './InterfaceBuilder';

export class InterfacesGenerator {
  private readonly spec: Spec;

  constructor(spec: Spec) {
    this.spec = spec;
  }

  buildInterfaces(): SwaxiosInterface[] {
    if (this.spec.definitions) {
      return Object.entries(this.spec.definitions).map(([name, definition]) => {
        return new InterfaceGenerator(name, definition).buildInterface();
      });
    }

    return [];
  }
}
