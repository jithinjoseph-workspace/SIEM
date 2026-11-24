import { TestBed } from '@angular/core/testing';

import { Evidence } from './evidence';

describe('Evidence', () => {
  let service: Evidence;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(Evidence);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
