import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Health } from './health';

describe('Health', () => {
  let component: Health;
  let fixture: ComponentFixture<Health>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Health]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Health);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
