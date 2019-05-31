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

export type Entity = Record<string, any> | string;

export interface CRUDEngine<F> {
  [index: string]: any;
  storeName: string;

  /**
   * Appends a string to an existing record.
   * @param tableName Table name
   * @param primaryKey Primary key of record which should get extended
   * @param additions Text to append
   * @returns Resolves with the primary key of the extended record.
   */
  append(tableName: string, primaryKey: string, additions: string): Promise<string>;

  /**
   * Initializes the store engine. This needs to be done prior to operating with it.
   * @param storeName Name of the store
   * @param settings Database-specific settings
   * @returns Resolves with the underlying (unwrapped) instance of a database.
   * @throws {UnsupportedError} Error when feature is not available on targeted platform.
   */
  init<T>(storeName: string, ...settings: T[]): Promise<F>;
  init<T, U>(storeName: string, ...settings: (T | U)[]): Promise<F>;
  init<T, U, V>(storeName: string, ...settings: (T | U | V)[]): Promise<F>;
  init<T, U, V, X>(storeName: string, ...settings: (T | U | V | X)[]): Promise<F>;

  /**
   * Deletes the store.
   * @returns Resolves if store got deleted.
   */
  purge(): Promise<void>;

  /**
   * Creates a record by its primary key within a table.
   * @param tableName Table name
   * @param primaryKey Primary key to be used to store the record
   * @param entity Any kind of object that should be stored
   * @returns Resolves with the primary key of the stored record.
   */
  create<T extends Entity>(tableName: string, primaryKey: string, entity: T): Promise<string>;

  /**
   * Deletes a record by its primary key within a table.
   * @param tableName Table name
   * @param primaryKey Primary key to be used to delete the record
   * @returns Resolves with the primary key of the deleted record.
   */
  delete(tableName: string, primaryKey: string): Promise<string>;

  /**
   * Deletes all records within a table.
   * @param tableName Table name
   * @returns Resolves with `true`, if all records have been removed.
   */
  deleteAll(tableName: string): Promise<boolean>;

  /**
   * Finds a record by its primary key within a table.
   * @param tableName Table name
   * @param primaryKey Primary key to query the record
   * @throws {RecordNotFoundError} Will be thrown if the record could not be found.
   * @returns Resolves with the record.
   */
  read<T extends Entity>(tableName: string, primaryKey: string): Promise<T>;

  /**
   * Reads all records from a table.
   * @param tableName Table name
   * @returns Resolves with an array of records from a table.
   */
  readAll<T extends Entity>(tableName: string): Promise<T[]>;

  /**
   * Returns all primary keys of records that are stored in a table.
   * @param tableName Table name
   * @returns Returns an array of primary keys.
   */
  readAllPrimaryKeys(tableName: string): Promise<string[]>;

  /**
   * Updates a record with a set of properties.
   * @param tableName Table name
   * @param primaryKey Primary key of record which should get updated
   * @param changes Updated properties that should be saved for the record
   * @returns Resolves with the primary key of the updated record.
   */
  update<T extends Entity>(tableName: string, primaryKey: string, changes: T): Promise<string>;

  /**
   * Updates a record with a set of properties.
   * If the record doesn't exist, The record will be created automatically.
   * @param tableName Table name
   * @param primaryKey Primary key of record which should get updated
   * @param changes Updated properties that should be saved for the record
   * @returns Resolves with the primary key of the updated record.
   */
  updateOrCreate<T extends Entity>(tableName: string, primaryKey: string, changes: T): Promise<string>;

  /**
   * Checks wether the engine is supported in the current environment.
   * @returns Resolves if supported, rejects if unsupported.
   */
  isSupported(): Promise<void>;
}
