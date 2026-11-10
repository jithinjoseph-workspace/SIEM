import { ComponentFixture, TestBed } from '@angular/core/testing';

import { Intel } from './intel';

describe('Intel', () => {
  let component: Intel;
  let fixture: ComponentFixture<Intel>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Intel]
    })
    .compileComponents();

    fixture = TestBed.createComponent(Intel);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
