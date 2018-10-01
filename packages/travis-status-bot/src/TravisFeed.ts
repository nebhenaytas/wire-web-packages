/*
 * Wire
 * Copyright (C) 2018 Wire Swiss GmbH
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

import axios from 'axios';
import * as logdown from 'logdown';

import {Options, TravisStatus} from './interfaces';

const defaultConfig: Required<Options> = {
  feedUrl: 'https://www.traviscistatus.com/index.json',
};

class TravisFeed {
  private readonly config: Required<Options>;
  private readonly logger: logdown.Logger;

  constructor(options?: Options) {
    this.config = {
      ...defaultConfig,
      ...options,
    };

    this.logger = logdown('@wireapp/travis-status-bot/TravisFeed', {
      logger: console,
      markdown: false,
    });
    this.logger.state.isEnabled = true;
  }

  public async getFeed(): Promise<TravisStatus> {
    const {data} = await axios.get<TravisStatus>(this.config.feedUrl);
    this.logger.info(`Got ${data.incidents.length} incidents and ${data.components.length} components.`);
    return data;
  }
}

export {TravisFeed};
