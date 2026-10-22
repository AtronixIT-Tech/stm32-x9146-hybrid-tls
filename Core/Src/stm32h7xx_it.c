/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    stm32h7xx_it.c
  * @brief   Interrupt Service Routines.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stm32h7xx_it.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/

/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
  /* USER CODE BEGIN NonMaskableInt_IRQn 0 */

  /* USER CODE END NonMaskableInt_IRQn 0 */
  /* USER CODE BEGIN NonMaskableInt_IRQn 1 */
   while (1)
  {
  }
  /* USER CODE END NonMaskableInt_IRQn 1 */
}

/* --- Shared fault dumper: prints stacked frame + SCB fault regs ---- */
#include <stdio.h>
extern void HAL_NVIC_SystemReset(void);

/* Called from the naked trampolines below with MSP/PSP pointer already
 * selected. Prints the faulting PC so we know exactly where ML-DSA /
 * wolfSSL died. After ~2 s worth of prints, issues a reset so the board
 * comes back alive and we can iterate. */
__attribute__((used))
static void fault_report(uint32_t *sp, const char *tag)
{
  uint32_t r0   = sp[0];
  uint32_t r1   = sp[1];
  uint32_t r2   = sp[2];
  uint32_t r3   = sp[3];
  uint32_t r12  = sp[4];
  uint32_t lr   = sp[5];
  uint32_t pc   = sp[6];
  uint32_t psr  = sp[7];

  uint32_t cfsr = SCB->CFSR;
  uint32_t hfsr = SCB->HFSR;
  uint32_t mmar = SCB->MMFAR;
  uint32_t bfar = SCB->BFAR;

  printf("\r\n*** %s ***\r\n", tag);
  printf("  PC   = 0x%08lX   LR   = 0x%08lX   PSR  = 0x%08lX\r\n",
         (unsigned long)pc, (unsigned long)lr, (unsigned long)psr);
  printf("  R0   = 0x%08lX   R1   = 0x%08lX   R2   = 0x%08lX   R3   = 0x%08lX\r\n",
         (unsigned long)r0, (unsigned long)r1, (unsigned long)r2, (unsigned long)r3);
  printf("  R12  = 0x%08lX   SP   = 0x%08lX\r\n",
         (unsigned long)r12, (unsigned long)(uintptr_t)sp);
  printf("  CFSR = 0x%08lX   HFSR = 0x%08lX\r\n",
         (unsigned long)cfsr, (unsigned long)hfsr);
  printf("  MMAR = 0x%08lX   BFAR = 0x%08lX\r\n",
         (unsigned long)mmar, (unsigned long)bfar);
  /* Decode the most common culprits. */
  if (cfsr & (1u << 0))  printf("  -> IACCVIOL (mem access instruction fetch)\r\n");
  if (cfsr & (1u << 1))  printf("  -> DACCVIOL (data access violation @ MMAR)\r\n");
  if (cfsr & (1u << 3))  printf("  -> MUNSTKERR (exception unstack mem fault)\r\n");
  if (cfsr & (1u << 4))  printf("  -> MSTKERR   (exception stack push mem fault = STACK OVERFLOW)\r\n");
  if (cfsr & (1u << 8))  printf("  -> IBUSERR   (instruction bus error)\r\n");
  if (cfsr & (1u << 9))  printf("  -> PRECISERR (precise data bus error @ BFAR)\r\n");
  if (cfsr & (1u <<10))  printf("  -> IMPRECISERR (imprecise data bus error)\r\n");
  if (cfsr & (1u <<11))  printf("  -> UNSTKERR  (unstack bus fault)\r\n");
  if (cfsr & (1u <<12))  printf("  -> STKERR    (stack bus fault = STACK OVERFLOW)\r\n");
  if (cfsr & (1u <<16))  printf("  -> UNDEFINSTR (undefined instruction)\r\n");
  if (cfsr & (1u <<17))  printf("  -> INVSTATE  (invalid EPSR.T/IT state)\r\n");
  if (cfsr & (1u <<18))  printf("  -> INVPC     (invalid PC load on exception return)\r\n");
  if (cfsr & (1u <<19))  printf("  -> NOCP      (no coprocessor)\r\n");
  if (cfsr & (1u <<24))  printf("  -> UNALIGNED (unaligned access)\r\n");
  if (cfsr & (1u <<25))  printf("  -> DIVBYZERO (integer divide by zero)\r\n");
  if (hfsr & (1u <<30))  printf("  -> FORCED    (escalated from bus/usage/mem)\r\n");
  printf("  ---- resetting in 100ms ----\r\n");
  for (volatile uint32_t i = 0; i < 2000000; i++) { __asm__ volatile("nop"); }
  HAL_NVIC_SystemReset();
  while (1) { }
}

/* Must be kept alive despite -ffunction-sections / --gc-sections — the
 * only references are from the inline assembly in the fault handlers
 * below, which the compiler doesn't see as C-level uses. */
__attribute__((used)) static const char s_tag_hard[]  = "HARDFAULT";
__attribute__((used)) static const char s_tag_mem[]   = "MEMMANAGE";
__attribute__((used)) static const char s_tag_bus[]   = "BUSFAULT";
__attribute__((used)) static const char s_tag_usage[] = "USAGEFAULT";

/**
  * @brief This function handles Hard fault interrupt.
  */
__attribute__((naked)) void HardFault_Handler(void)
{
  __asm__ volatile (
      "tst lr, #4          \n"
      "ite eq              \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "ldr   r1, =s_tag_hard \n"
      "b     fault_report  \n"
  );
}

/**
  * @brief This function handles Memory management fault.
  */
__attribute__((naked)) void MemManage_Handler(void)
{
  __asm__ volatile (
      "tst lr, #4          \n"
      "ite eq              \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "ldr   r1, =s_tag_mem \n"
      "b     fault_report  \n"
  );
}

/**
  * @brief This function handles Pre-fetch fault, memory access fault.
  */
__attribute__((naked)) void BusFault_Handler(void)
{
  __asm__ volatile (
      "tst lr, #4          \n"
      "ite eq              \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "ldr   r1, =s_tag_bus \n"
      "b     fault_report  \n"
  );
}

/**
  * @brief This function handles Undefined instruction or illegal state.
  */
__attribute__((naked)) void UsageFault_Handler(void)
{
  __asm__ volatile (
      "tst lr, #4          \n"
      "ite eq              \n"
      "mrseq r0, msp       \n"
      "mrsne r0, psp       \n"
      "ldr   r1, =s_tag_usage \n"
      "b     fault_report  \n"
  );
}

/**
  * @brief This function handles System service call via SWI instruction.
  */
void SVC_Handler(void)
{
  /* USER CODE BEGIN SVCall_IRQn 0 */

  /* USER CODE END SVCall_IRQn 0 */
  /* USER CODE BEGIN SVCall_IRQn 1 */

  /* USER CODE END SVCall_IRQn 1 */
}

/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
  /* USER CODE BEGIN DebugMonitor_IRQn 0 */

  /* USER CODE END DebugMonitor_IRQn 0 */
  /* USER CODE BEGIN DebugMonitor_IRQn 1 */

  /* USER CODE END DebugMonitor_IRQn 1 */
}

/**
  * @brief This function handles Pendable request for system service.
  */
void PendSV_Handler(void)
{
  /* USER CODE BEGIN PendSV_IRQn 0 */

  /* USER CODE END PendSV_IRQn 0 */
  /* USER CODE BEGIN PendSV_IRQn 1 */

  /* USER CODE END PendSV_IRQn 1 */
}

/**
  * @brief This function handles System tick timer.
  */
void SysTick_Handler(void)
{
  /* USER CODE BEGIN SysTick_IRQn 0 */

  /* USER CODE END SysTick_IRQn 0 */
  HAL_IncTick();
  /* USER CODE BEGIN SysTick_IRQn 1 */

  /* USER CODE END SysTick_IRQn 1 */
}

/******************************************************************************/
/* STM32H7xx Peripheral Interrupt Handlers                                    */
/* Add here the Interrupt Handlers for the used peripherals.                  */
/* For the available peripheral interrupt handler names,                      */
/* please refer to the startup file (startup_stm32h7xx.s).                    */
/******************************************************************************/

/**
  * @brief This function handles EXTI line[15:10] interrupts.
  */
void EXTI15_10_IRQHandler(void)
{
  /* USER CODE BEGIN EXTI15_10_IRQn 0 */

  /* USER CODE END EXTI15_10_IRQn 0 */
  BSP_PB_IRQHandler(BUTTON_USER);
  /* USER CODE BEGIN EXTI15_10_IRQn 1 */

  /* USER CODE END EXTI15_10_IRQn 1 */
}

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */
