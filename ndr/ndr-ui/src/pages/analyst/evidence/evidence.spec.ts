import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Evidence } from './evidence';

describe('Evidence', () => {
  let component: Evidence;
  let fixture: ComponentFixture<Evidence>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Evidence]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Evidence);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
